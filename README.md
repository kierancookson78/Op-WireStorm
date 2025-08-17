# Building and Running Instructions
## Prerequisites
Firstly, you will need to install the g++ compiler:
``` bash
sudo apt install build-essential
```
Then install Python 3.12:
``` bash
sudo apt install python3.12
```
Next you will need to install git so you can clone the repository:
``` bash
sudo apt install git
```
Then install the gdb debugger:
``` bash
sudo apt install gdb
```
## Building
Firstly, you will need to clone the repository:
``` bash
git clone https://github.com/kierancookson78/Op-WireStorm.git
cd Op-WireStorm
```
Now to build you run:
``` bash
g++ wirestorm.cpp -o wirestorm
```
## Running
To run the proxy you run:
``` bash
./wirestorm
```
from within the projects root directory

Open a new terminal window with the other still open then run the compulsory test cases:
``` bash
cd Op-WireStorm
python3.12 tests.py
```
If the test was successful you should see:

<img width="983" height="572" alt="successful test 1" src="https://github.com/user-attachments/assets/940d96c9-4a9f-40f4-af1e-9698cab342b7" />

To run the optional extended test cases run:
``` bash
cd wire-storm-reloaded-1.0.0
python3.12 tests.py
```
from within the projects root directory
If the test was successful you should see:

<img width="796" height="383" alt="successful test 2" src="https://github.com/user-attachments/assets/5b56e62e-d240-4d35-97af-c02c8e3e8ee6" />
