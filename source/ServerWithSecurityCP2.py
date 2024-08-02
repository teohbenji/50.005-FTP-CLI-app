import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import logging
import psutil

used_nonces = set()

# For logging
logging.basicConfig(filename='logs/server_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_event(event_name):
    cpu_usage = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    network_info = psutil.net_io_counters()
    current_time = datetime.now()
    logging.info(f'{current_time} {event_name}')
    logging.info(f'CPU Usage: {cpu_usage}%, Memory Usage: {memory_info.percent}%, Network Sent: {network_info.bytes_sent}, Network Received: {network_info.bytes_recv}')


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                cipher = None # Used to decrypt encrypted file data

                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            encrypted_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            # Decrypt data
                            log_event("Receiving encrypted data")
                            file_data = cipher.decrypt(encrypted_data)
                            
                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(f"recv_files/{filename}", mode="wb") as fp:
                                fp.write(file_data)

                            log_event(f"Finished receiving file in {(time.time() - start_time)}s!")
                            print(f"Finished receiving file in {(time.time() - start_time)}s!")

                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            # If the packet is for authentication

                            # Receive M1 = length of authentication message in bytes
                            message_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )

                            # Receive M2 = authentication message
                            message_data = read_bytes(client_socket, message_len)

                            # Extract nonce from the end of the message
                            nonce_size = 16 
                            nonce = message_data[-nonce_size:]

                            # Validate the nonce
                            if not is_nonce_valid(nonce):
                                print("Invalid or reused nonce sent by client")
                                print("Closing connection...")
                                client_socket.close()
                                s.close()

                            with open('source/auth/_private_key.pem', 'rb') as key_file:
                                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                            
                            with open('source/auth/server_signed.crt', 'rb') as cert_file:
                                signed_cert_bytes = cert_file.read()

                            signed_message = sign_message(message_data, private_key)

                            # Send M1 = size of signed authentication message in bytes
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))

                            # Send M2 = signed authentication message
                            client_socket.sendall(signed_message)

                            # Send M1 = size of signed certificate in bytes
                            client_socket.sendall(convert_int_to_bytes(len(signed_cert_bytes)))

                            # Send M2 = signed certificate file
                            client_socket.sendall(signed_cert_bytes)
                            break
                        case 4:
                            # Mode 4 
                            # Receive M1 = size of encrypted generated session key in bytes
                            encrypted_session_key_len = convert_bytes_to_int(read_bytes(client_socket, 8))

                            # Receive M2 = encrypted generated session key
                            encrypted_session_key = read_bytes(client_socket, encrypted_session_key_len)

                            # Decrypt the session key
                            session_key = private_key.decrypt(
                                encrypted_session_key,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
                            )

                            cipher = Fernet(session_key)

    except Exception as e:
        print(e)
        s.close()

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)

# Sign the message with private key and pad the message
def sign_message(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Check if nonce sent by client has been used before
def is_nonce_valid(nonce):
    if nonce in used_nonces:
        return False
    
    used_nonces.add(nonce)
    return True
    
if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
