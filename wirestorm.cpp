#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// CTMP Protocol Constants
const uint8_t MAGIC_BYTE = 0xCC;
const size_t HEADER_SIZE = 8;

// Server Configuration
const uint16_t SOURCE_PORT = 33333;
const uint16_t DESTINATION_PORT = 44444;
const uint16_t MAX_PAYLOAD_SIZE = 65535;

// Structure to hold a complete CTMP message
struct CTMPMessage {
  std::vector<uint8_t> data;
};

// Function declaration
uint16_t calculate_checksum(uint8_t* header, uint8_t* data,
                            uint16_t data_length);

// Global shared resources
std::vector<int> destination_clients;
std::mutex clients_mutex;
std::queue<CTMPMessage> message_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

// Helper function to read a specific number of bytes from a socket
ssize_t read_n_bytes(int sockfd, uint8_t* buffer, size_t n_bytes,
                     int timeout_sec) {
  size_t bytes_read = 0;

  struct timeval tv;
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

  while (bytes_read < n_bytes) {
    ssize_t result = recv(sockfd, buffer + bytes_read, n_bytes - bytes_read, 0);
    if (result == 0) {
      return 0;
    } else if (result < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        std::cerr << "Read timeout on socket " << sockfd << std::endl;
        return -1;
      } else if (errno == EINTR) {
        continue;
      } else {
        std::cerr << "Error reading from socket " << sockfd << ": "
                  << strerror(errno) << std::endl;
        return -1;
      }
    }
    bytes_read += result;
  }
  return bytes_read;
}

// Thread function for listening to the single source client
void source_listener_thread() {
  int server_fd;
  struct sockaddr_in address;
  int opt = 1;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    std::cerr << "Source listener: Socket creation failed" << std::endl;
    return;
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    std::cerr << "Source listener: setsockopt failed" << std::endl;
    close(server_fd);
    return;
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(SOURCE_PORT);

  if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
    std::cerr << "Source listener: Bind failed" << std::endl;
    close(server_fd);
    return;
  }

  if (listen(server_fd, 1) < 0) {
    std::cerr << "Source listener: Listen failed" << std::endl;
    close(server_fd);
    return;
  }

  std::cout << "Source listener: Listening on 127.0.0.1:" << SOURCE_PORT
            << std::endl;

  while (true) {
    std::cout << "Source listener: Waiting for a source client connection..."
              << std::endl;
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    if ((client_socket = accept(server_fd, (struct sockaddr*)&client_addr,
                                &client_addr_len)) < 0) {
      std::cerr << "Source listener: Accept failed" << std::endl;
      continue;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::cout << "Source listener: Source client connected from " << client_ip
              << ":" << ntohs(client_addr.sin_port) << std::endl;

    uint8_t header_buf[HEADER_SIZE];
    std::vector<uint8_t> data_buf;

    while (true) {
      ssize_t bytes_read =
          read_n_bytes(client_socket, header_buf, HEADER_SIZE, 5);
      if (bytes_read <= 0) {
        std::cerr << "Source listener: Source client " << client_ip
                  << " disconnected or read error/timeout." << std::endl;
        break;
      }

      uint8_t magic = header_buf[0];
      uint8_t options = header_buf[1];
      uint16_t length =
          (static_cast<uint16_t>(header_buf[2]) << 8) | header_buf[3];
      uint16_t checksum =
          (static_cast<uint16_t>(header_buf[4]) << 8) | header_buf[5];

      bool is_sensitive = (options & 0x40) != 0;

      if (magic != MAGIC_BYTE) {
        std::cerr
            << "Source listener: Invalid MAGIC byte. Dropping message from "
            << client_ip << std::endl;
        continue;
      }

      if (length > MAX_PAYLOAD_SIZE) {
        std::cerr << "Source listener: Excessive LENGTH. Dropping message from "
                  << client_ip << std::endl;
        continue;
      }

      data_buf.resize(length);
      bytes_read = read_n_bytes(client_socket, data_buf.data(), length, 5);
      if (bytes_read <= 0) {
        std::cerr << "Source listener: Source client " << client_ip
                  << " disconnected during data payload." << std::endl;
        break;
      }

      // Checksum validation for sensitive messages
      if (is_sensitive) {
        uint8_t header_copy[HEADER_SIZE];
        memcpy(header_copy, header_buf, HEADER_SIZE);
        header_copy[4] = 0x00;
        header_copy[5] = 0x00;

        uint16_t calculated_checksum =
            calculate_checksum(header_copy, data_buf.data(), length);

        if (calculated_checksum != checksum) {
          std::cerr << "Source listener: Invalid CHECKSUM. Dropping sensitive "
                       "message from "
                    << client_ip << std::endl;
          continue;
        }
      }

      CTMPMessage full_message;
      full_message.data.reserve(HEADER_SIZE + length);
      full_message.data.insert(full_message.data.end(), header_buf,
                               header_buf + HEADER_SIZE);
      full_message.data.insert(full_message.data.end(), data_buf.begin(),
                               data_buf.end());

      {
        std::lock_guard<std::mutex> lock(queue_mutex);
        message_queue.push(full_message);
      }
      queue_cv.notify_one();
    }
    close(client_socket);
    std::cout << "Source listener: Source client " << client_ip
              << " disconnected. Waiting for new connection..." << std::endl;
  }
  close(server_fd);
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

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
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

  if (listen(server_fd, 10) < 0) {
    std::cerr << "Destination listener: Listen failed" << std::endl;
    close(server_fd);
    return;
  }

  std::cout << "Destination listener: Listening on 127.0.0.1:"
            << DESTINATION_PORT << std::endl;

  while (true) {
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    if ((client_socket = accept(server_fd, (struct sockaddr*)&client_addr,
                                &client_addr_len)) < 0) {
      std::cerr << "Destination listener: Accept failed" << std::endl;
      continue;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::cout << "Destination listener: New destination client connected from "
              << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;

    {
      std::lock_guard<std::mutex> lock(clients_mutex);
      destination_clients.push_back(client_socket);
      std::cout << "Destination listener: Added client " << client_socket
                << ". Total clients: " << destination_clients.size()
                << std::endl;
    }
  }
  close(server_fd);
}

// Thread function for forwarding messages to destination clients
void message_forwarder_thread() {
  std::cout << "Message forwarder: Started and waiting for messages."
            << std::endl;
  while (true) {
    CTMPMessage message_to_send;

    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      queue_cv.wait(lock, [] { return !message_queue.empty(); });
      message_to_send = message_queue.front();
      message_queue.pop();
    }

    std::vector<int> active_clients;
    {
      std::lock_guard<std::mutex> lock(clients_mutex);
      for (int client_socket : destination_clients) {
        ssize_t result = send(client_socket, message_to_send.data.data(),
                              message_to_send.data.size(), MSG_NOSIGNAL);
        if (result == (ssize_t)message_to_send.data.size()) {
          active_clients.push_back(client_socket);
        } else {
          std::cerr << "Forwarder: Failed to send to client " << client_socket
                    << std::endl;
          close(client_socket);
        }
      }
      destination_clients = active_clients;
    }
  }
}

// Calculate 16-bit one's complement checksum
uint16_t calculate_checksum(uint8_t* header, uint8_t* data,
                            uint16_t data_length) {
  uint32_t sum = 0;

  uint8_t header_copy[HEADER_SIZE];
  memcpy(header_copy, header, HEADER_SIZE);
  header_copy[4] = 0xCC;
  header_copy[5] = 0xCC;

  for (int i = 0; i < HEADER_SIZE; i += 2) {
    uint16_t word =
        (static_cast<uint16_t>(header_copy[i]) << 8) | header_copy[i + 1];
    sum += word;
  }

  for (uint16_t i = 0; i < data_length; i += 2) {
    uint16_t word;
    if (i + 1 < data_length) {
      word = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
    } else {
      word = static_cast<uint16_t>(data[i]) << 8;
    }
    sum += word;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

int main() {
  std::cout << "Starting CoreTech Message Protocol Proxy Server (C++)..."
            << std::endl;

  std::thread source_thread(source_listener_thread);
  source_thread.detach();

  std::thread destination_thread(destination_listener_thread);
  destination_thread.detach();

  std::thread forwarder_thread(message_forwarder_thread);
  forwarder_thread.detach();

  std::cout << "Server initialized. Press Ctrl+C to exit." << std::endl;
  while (true) {
    std::this_thread::sleep_for(std::chrono::minutes(1));
  }

  return 0;
}