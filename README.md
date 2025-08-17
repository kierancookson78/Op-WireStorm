# Building and Running Instructions
## prerequisites
First install and IDE such as Visual Studio Code:
``` bash
sudo snap install --classic code
```
Next you will need to install the g++ compiler:
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
To run the optional extended test cases run:
``` bash
cd wire-storm-reloaded-1.0.0
python3.12 tests.py
```
from within the projects root directory
