[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/klGEfp-A)

# 50.005 Programming Assignment 2

This assignment requires knowledge from Network Security and basic knowledge in Python.

## Secure FTP != HTTPs

Note that you will be implementing Secure FTP as your own whole new application layer protocol. In NO WAY we are relying on HTTP/s. Please do not confuse the materials, you don't need to know materials in Week 11 and 12 before getting started.

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

If `ensurepip` is not available, you need to install it, e.g with Ubuntu:

```
# Adjust for your python version
sudo apt-get install python3.10-venv
```

### Run `./cleanup.,sh`

Run this in the root project directory:

```
chmod +x ./cleanup.sh
./cleanup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

In two separate shell sessions, run the server first(assuming you're in root project directory):

```
python3 source/ServerWithoutSecurity.py
```

and then the client afterwards:

```
python3 source/ClientWithoutSecurity.py
```

### Using different machines

You can also host the Server file in another computer:

```sh
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

The client computer can connect to it using the command:

```sh
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:

```
exit
```

Do not forget to spawn the shell again if you'd like to restart the assignment.

### Uploading files
In the shell session with the client code running, you will be first prompted to choose the language. Enter 0 for English, 1 for Malay and 2 for Filipino.
```
Code here
```
Afterwards, enter the filepath of the file you want to upload. Example using file.txt in files folder
```
Enter a filename to send (enter -1 to exit):files/file.txt
```
Upon successful file upload, the following will be printed out on the server side
```
Receiving file...
Finished receiving file in 0.028443574905395508s!
```
To exit the program, type -1 to exit the program at any time. Two messages will then be printed out, and the server program will stop running as well.
Alternatively, force close the app using CTRL+C
```
Closing connection...
Program took 1.9450325965881348s to run.
```


## Sustainability
This program promotes sustainability by making use of best practices for the writing of code, and logging of the file transfer process on the server side.

### Best code practices

**1. Proper use of context managers:**
    Adding the `with` statement to the opening of sockets and files ensures proper resource management, preventing resource leaks.

```
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    ...

with open('source/auth/cacsertificate.crt', 'rb') as cert_file:
    ...
```

**2. Graceful handling of exceptions:**
    Exception handling manages errors and provides meaningful messages to the user for a smoother debugging experience.

```
try:
    public_key.verify(
        msg_m2,
        filename_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
        hashes.SHA256() 
    )

print("Successfully verified certificate")

except Exception as e:
    print(f"Verification failed: {e}")
    s.sendall(convert_int_to_bytes(2))
```

**3. Use of set data structure:**
    A set is used in the server code to store the used nonces, as time complexity for all operations performed on the set is O(1) (insertion, membership check).

```
used_nonces = set()
if nonce in used_nonces: # Membership check
used_nonces.add(nonce) # Addition
```

### Logging

The `log_event` function logs various system performance metrics and events during data processing. It captures:

- **CPU Usage**: The percentage of CPU utilization at the time of the event.
- **Memory Usage**: The percentage of memory used.
- **Network Sent**: The total amount of data sent over the network.
- **Network Received**: The total amount of data received over the network.
Usage:
```
log_event(event_name)
```
Example log output:

```
2024-08-06 22:19:43,903 - INFO - 2024-08-06 22:19:43.903463 Finished receiving file in 0.018079519271850586s!
2024-08-06 22:19:43,903 - INFO - CPU Usage: 0.0%, Memory Usage: 64.4%, Network Sent: 28377966, Network Received: 117408047
```
## Inclusivity
The app includes a feature that allows users to choose their preferred language upon startup of the client program. Users can select English, Malay or Filipino. For example
```
English: Public key extracted from CA certificate.
```
```
Malay: Kunci awam diekstrak dari sijil CA.
```
```
Filipino: Public key na kinuha mula sa CA certificate.
```
