#include <iostream>     // For standard input/output operations (cout, cerr)
#include <vector>       // For dynamic arrays (e.g., storing client sockets)
#include <thread>       // For multi-threading (source listener, destination listener, forwarder)
#include <mutex>        // For protecting shared resources (destination client list)
#include <queue>        // For the message queue between source and forwarder threads
#include <condition_variable> // For signaling between threads (message queue)
#include <cstring>      // For memory manipulation (memcpy, memset)
#include <stdexcept>    // For standard exceptions
#include <cerrno>       // For errno constants (EWOULDBLOCK, EAGAIN, etc.)

// Networking specific headers
#include <sys/socket.h> // For socket creation, bind, listen, accept, connect, send, recv
#include <netinet/in.h> // For sockaddr_in structure, htons, htonl
#include <arpa/inet.h>  // For inet_ntoa (converting IP address to string)
#include <unistd.h>     // For close (closing sockets)
#include <fcntl.h>      // For fcntl (setting non-blocking sockets, if needed)

// CTMP Protocol Constants
const uint8_t MAGIC_BYTE = 0xCC;
const uint8_t PADDING_BYTE = 0x00;
const size_t HEADER_SIZE = 8; // MAGIC (1 byte) + PADDING (1 byte) + LENGTH (2 bytes)

// Server Configuration
const uint16_t SOURCE_PORT = 33333;
const uint16_t DESTINATION_PORT = 44444;
// Maximum allowed data length (excluding header).
// If an incoming message's LENGTH field exceeds this, the message is dropped.
const uint16_t MAX_PAYLOAD_SIZE = 65535; // Maximum for 16-bit length field

// Structure to hold a complete CTMP message
struct CTMPMessage {
    std::vector<uint8_t> data; // Stores the full message (header + payload)
};

// Function declarations
uint16_t calculate_checksum(uint8_t* header, uint8_t* data, uint16_t data_length);
uint16_t calculate_checksum_validation(uint8_t* header, uint8_t* data, uint16_t data_length);

// Global shared resources for inter-thread communication and client management
std::vector<int> destination_clients; // List of active destination client sockets
std::mutex clients_mutex;             // Mutex to protect 'destination_clients' vector

std::queue<CTMPMessage> message_queue; // Queue for messages from source to forwarder
std::mutex queue_mutex;               // Mutex to protect 'message_queue'
std::condition_variable queue_cv;     // Condition variable to signal new messages in queue

// Helper function to set a socket to non-blocking mode
bool set_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "Error getting socket flags: " << strerror(errno) << std::endl;
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cerr << "Error setting socket non-blocking: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

// Helper function to read a specific number of bytes from a socket
// Handles partial reads and timeouts
ssize_t read_n_bytes(int sockfd, uint8_t* buffer, size_t n_bytes, int timeout_sec) {
    size_t bytes_read = 0;

    // Set read timeout
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    while (bytes_read < n_bytes) {
        ssize_t result = recv(sockfd, buffer + bytes_read, n_bytes - bytes_read, 0);
        if (result == 0) {
            // Connection closed by peer
            return 0;
        }
        else if (result < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Timeout occurred or no data available immediately
                std::cerr << "Read timeout on socket " << sockfd << std::endl;
                return -1; // Indicate timeout
            }
            else if (errno == EINTR) {
                // Interrupted system call, retry
                continue;
            }
            else {
                // Other error
                std::cerr << "Error reading from socket " << sockfd << ": " << strerror(errno) << std::endl;
                return -1;
            }
        }
        bytes_read += result;
    }
    return bytes_read;
}

// Helper function to write a specific number of bytes to a socket
// Handles partial writes and timeouts
ssize_t write_n_bytes(int sockfd, const uint8_t* buffer, size_t n_bytes, int timeout_sec) {
    size_t bytes_sent = 0;

    // Set write timeout
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    while (bytes_sent < n_bytes) {
        ssize_t result = send(sockfd, buffer + bytes_sent, n_bytes - bytes_sent, 0);
        if (result == 0) {
            // Connection closed by peer (unexpected for send)
            return 0;
        }
        else if (result < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Timeout occurred or buffer full
                std::cerr << "Write timeout on socket " << sockfd << std::endl;
                return -1; // Indicate timeout
            }
            else if (errno == EINTR) {
                // Interrupted system call, retry
                continue;
            }
            else {
                // Other error
                std::cerr << "Error writing to socket " << sockfd << ": " << strerror(errno) << std::endl;
                return -1;
            }
        }
        bytes_sent += result;
    }
    return bytes_sent;
}


// Thread function for listening to the single source client
void source_listener_thread() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1; // For setsockopt to reuse address

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Source listener: Socket creation failed" << std::endl;
        return;
    }

    // Set socket options to reuse address and port, preventing "Address already in use" errors
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Source listener: setsockopt failed" << std::endl;
        close(server_fd);
        return;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    address.sin_port = htons(SOURCE_PORT); // Convert port to network byte order

    // Bind the socket to the specified IP and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Source listener: Bind failed" << std::endl;
        close(server_fd);
        return;
    }

    // Listen for incoming connections (max 1 pending connection for source)
    if (listen(server_fd, 1) < 0) {
        std::cerr << "Source listener: Listen failed" << std::endl;
        close(server_fd);
        return;
    }

    std::cout << "Source listener: Listening on 127.0.0.1:" << SOURCE_PORT << std::endl;

    while (true) {
        std::cout << "Source listener: Waiting for a source client connection..." << std::endl;
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Accept a single incoming connection
        if ((client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
            std::cerr << "Source listener: Accept failed" << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        std::cout << "Source listener: Source client connected from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;

        uint8_t header_buf[HEADER_SIZE];
        std::vector<uint8_t> data_buf;

        while (true) {
            // Read the 8-byte header
            ssize_t bytes_read = read_n_bytes(client_socket, header_buf, HEADER_SIZE, 5);
            if (bytes_read <= 0) {
                std::cerr << "Source listener: Source client " << client_ip << " disconnected or read error/timeout." << std::endl;
                break;
            }

            // Parse the new header format
            uint8_t magic = header_buf[0];
            uint8_t options = header_buf[1];
            uint16_t length = (static_cast<uint16_t>(header_buf[2]) << 8) | header_buf[3];
            uint16_t checksum = (static_cast<uint16_t>(header_buf[4]) << 8) | header_buf[5];
            uint16_t padding = (static_cast<uint16_t>(header_buf[6]) << 8) | header_buf[7];

            // Extract sensitive bit (bit 6 only, as per test data)
            bool is_sensitive = (options & 0x40) != 0;

            // --- CTMP Header Validation ---
            if (magic != MAGIC_BYTE) {
                std::cerr << "Source listener: Invalid MAGIC byte (0x" << std::hex << (int)magic 
                          << " received, expected 0x" << (int)MAGIC_BYTE << "). Dropping message from " 
                          << client_ip << std::endl;
                continue;
            }
            
            if (length > MAX_PAYLOAD_SIZE) {
                std::cerr << "Source listener: Excessive LENGTH (" << length 
                          << " bytes received, max allowed is " << MAX_PAYLOAD_SIZE 
                          << " bytes). Dropping message from " << client_ip << std::endl;
                continue;
            }

            // Read the data payload
            data_buf.resize(length);
            bytes_read = read_n_bytes(client_socket, data_buf.data(), length, 5);
            if (bytes_read <= 0) {
                std::cerr << "Source listener: Source client " << client_ip 
                          << " disconnected or read error/timeout during data payload." << std::endl;
                break;
            }

            // Checksum validation for sensitive messages
            if (is_sensitive) {
                // For one's complement checksum validation
                // Replace the checksum field with zeros, then calculate
                uint8_t header_copy[HEADER_SIZE];
                memcpy(header_copy, header_buf, HEADER_SIZE);
                header_copy[4] = 0x00;  // Zero out checksum field
                header_copy[5] = 0x00;
                
                uint16_t calculated_checksum = calculate_checksum(header_copy, data_buf.data(), length);
                
                if (calculated_checksum != checksum) {
                    std::cerr << "Source listener: Invalid CHECKSUM (received: 0x" << std::hex << checksum 
                              << ", calculated: 0x" << calculated_checksum 
                              << "). Dropping sensitive message from " << client_ip << std::endl;
                    continue;
                }
            }

            // Message is valid, forward it
            CTMPMessage full_message;
            full_message.data.reserve(HEADER_SIZE + length);
            full_message.data.insert(full_message.data.end(), header_buf, header_buf + HEADER_SIZE);
            full_message.data.insert(full_message.data.end(), data_buf.begin(), data_buf.end());

            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                message_queue.push(full_message);
            }
            queue_cv.notify_one();
        }
        close(client_socket); // Close the disconnected source client socket
        std::cout << "Source listener: Source client " << client_ip << " disconnected. Waiting for new connection..." << std::endl;
    }
    close(server_fd); // Close the server listener socket (though unreachable in current loop)
}

// Thread function for listening to and accepting destination clients
void destination_listener_thread() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Destination listener: Socket creation failed" << std::endl;
        return;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Destination listener: setsockopt failed" << std::endl;
        close(server_fd);
        return;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DESTINATION_PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Destination listener: Bind failed" << std::endl;
        close(server_fd);
        return;
    }

    if (listen(server_fd, 10) < 0) { // Allow up to 10 pending connections
        std::cerr << "Destination listener: Listen failed" << std::endl;
        close(server_fd);
        return;
    }

    std::cout << "Destination listener: Listening on 127.0.0.1:" << DESTINATION_PORT << std::endl;

    while (true) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        if ((client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
            std::cerr << "Destination listener: Accept failed" << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        std::cout << "Destination listener: New destination client connected from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;
        std::cout << "Destination listener: Client " << client_socket << " connected from " 
                  << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;

        // Add new client socket to the shared vector
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            destination_clients.push_back(client_socket);
            std::cout << "Destination listener: Added client " << client_socket 
                      << ". Total clients: " << destination_clients.size() << std::endl;
        }
    }
    close(server_fd);
}

// Thread function for forwarding messages to destination clients
void message_forwarder_thread() {
    std::cout << "Message forwarder: Started and waiting for messages." << std::endl;
    while (true) {
        CTMPMessage message_to_send;
        
        std::cout << "Forwarder: Waiting for message in queue..." << std::endl;
        
        // Wait for and immediately pop the message
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [] { return !message_queue.empty(); });
            message_to_send = message_queue.front();
            message_queue.pop();
        }

        std::cout << "Forwarder: Got message of size " << message_to_send.data.size() 
                  << ", checking for clients..." << std::endl;

        // Send to all active clients immediately
        std::vector<int> active_clients;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::cout << "Forwarder: Found " << destination_clients.size() << " destination clients" << std::endl;
            
            for (int client_socket : destination_clients) {
                std::cout << "Forwarder: Sending to client socket " << client_socket << std::endl;
                ssize_t result = send(client_socket, message_to_send.data.data(), message_to_send.data.size(), MSG_NOSIGNAL);
                if (result == (ssize_t)message_to_send.data.size()) {
                    active_clients.push_back(client_socket);
                    std::cout << "Forwarder: Successfully sent " << result << " bytes to client " << client_socket << std::endl;
                } else {
                    std::cerr << "Forwarder: Failed to send to client " << client_socket 
                              << " (sent " << result << " of " << message_to_send.data.size() << " bytes)" << std::endl;
                    close(client_socket);
                }
            }
            destination_clients = active_clients;
        }
        
        std::cout << "Forwarder: Message forwarded to " << active_clients.size() << " active clients." << std::endl;
    }
}

// Calculate 16-bit one's complement checksum
uint16_t calculate_checksum(uint8_t* header, uint8_t* data, uint16_t data_length) {
    uint32_t sum = 0;
    
    // Create a copy of header with checksum field set to 0xCCCC
    uint8_t header_copy[HEADER_SIZE];
    memcpy(header_copy, header, HEADER_SIZE);
    header_copy[4] = 0xCC;
    header_copy[5] = 0xCC;
    
    // Sum header words (4 x 16-bit words)
    for (int i = 0; i < HEADER_SIZE; i += 2) {
        uint16_t word = (static_cast<uint16_t>(header_copy[i]) << 8) | header_copy[i + 1];
        sum += word;
    }
    
    // Sum data words
    for (uint16_t i = 0; i < data_length; i += 2) {
        uint16_t word;
        if (i + 1 < data_length) {
            word = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
        } else {
            // Odd number of bytes, pad with zero
            word = static_cast<uint16_t>(data[i]) << 8;
        }
        sum += word;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Return one's complement
    return static_cast<uint16_t>(~sum);
}

// Calculate checksum for validation (includes the actual checksum in the header)
uint16_t calculate_checksum_validation(uint8_t* header, uint8_t* data, uint16_t data_length) {
    uint32_t sum = 0;
    
    // Use the header as-is (including the actual checksum)
    // Sum header words (4 x 16-bit words)
    for (int i = 0; i < HEADER_SIZE; i += 2) {
        uint16_t word = (static_cast<uint16_t>(header[i]) << 8) | header[i + 1];
        sum += word;
    }
    
    // Sum data words
    for (uint16_t i = 0; i < data_length; i += 2) {
        uint16_t word;
        if (i + 1 < data_length) {
            word = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
        } else {
            // Odd number of bytes, pad with zero
            word = static_cast<uint16_t>(data[i]) << 8;
        }
        sum += word;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Return one's complement
    return static_cast<uint16_t>(~sum);
}

int main() {
    std::cout << "Starting CoreTech Message Protocol Proxy Server (C++)..." << std::endl;

    // Create and detach threads
    std::thread source_thread(source_listener_thread);
    source_thread.detach();

    std::thread destination_thread(destination_listener_thread);
    destination_thread.detach();

    // Use only ONE forwarder thread to avoid race conditions
    std::thread forwarder_thread(message_forwarder_thread);
    forwarder_thread.detach();

    std::cout << "Server initialized. Press Ctrl+C to exit." << std::endl;
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }

    return 0;
}