import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


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


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # Authenticate method mode 3
        s.sendall(convert_int_to_bytes(3))
        nonce = secrets.token_bytes(16)
        filename_bytes = bytes("test", encoding="utf8") + nonce # Added nonce to prevent replay attacks
        s.sendall(convert_int_to_bytes(len(filename_bytes)))
        s.sendall(filename_bytes)

        msg_m1_size = int.from_bytes(s.recv(8), byteorder='big')
        msg_m2 = s.recv(msg_m1_size)
        cert_m1_size = int.from_bytes(s.recv(8), byteorder='big')
        cert_m2 = s.recv(cert_m1_size)

        with open('source/auth/cacsertificate.crt', 'rb') as cert_file:
            ca_cert_data = cert_file.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

        # Extract CA public key
        ca_public_key = ca_cert.public_key()
        print("Public key extracted from CA certificate.")

        # Load the received certificate directly from bytes
        received_cert = x509.load_pem_x509_certificate(cert_m2, default_backend())

        cert_m2_signature = received_cert.signature
        cert_m2_tbs_certificate = received_cert.tbs_certificate_bytes
        try:
            current_time = datetime.now()
            if received_cert.not_valid_before <= current_time <= received_cert.not_valid_after:
                print("Certificate is within the validity period.")
            else:
                print("Certificate is expired or not yet valid.")
                raise Exception()
            ca_public_key.verify(
                cert_m2_signature,
                cert_m2_tbs_certificate,
                padding.PKCS1v15(),  # Padding scheme used by the CA
                hashes.SHA256()      # Hash algorithm used by the CA
            )
            print("Certificate verification successful.")

        except Exception as e:
            print(f"Certificate verification failed: {e}")
            s.sendall(convert_int_to_bytes(2))
            
        # Extract the public key from the received certificate
        public_key = received_cert.public_key()    
        try:
            public_key.verify(
                msg_m2,
                filename_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
                hashes.SHA256() 
            )
            print("Works")
        except Exception as e:
            print(f"Verification failed: {e}")
            s.sendall(convert_int_to_bytes(2))

        # Mode 4: Generate the session key, encrypt it and then send it 
        session_key = Fernet.generate_key()
        cipher = Fernet(session_key)

        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )

        s.sendall(convert_int_to_bytes(4))
        s.sendall(convert_int_to_bytes(len(encrypted_session_key)))
        s.sendall(encrypted_session_key)

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                encrypted_data = cipher.encrypt(data)
                    
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data)))
                s.sendall(encrypted_data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")



if __name__ == "__main__":
    main(sys.argv[1:])
