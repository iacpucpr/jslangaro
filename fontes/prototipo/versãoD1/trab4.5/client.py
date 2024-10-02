import socket
import ssl
import pyotp
import hashlib
import base64
import time

SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443

# Global counter for the client
client_counter = 0

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

def generate_seed(poetry_lines, otp):
    seed = ''.join(poetry_lines[3][:16])
    if len(poetry_lines[0]) > 57:
        seed += poetry_lines[0][57]
    
    num_lines = len(poetry_lines)
    if int(otp[-2:]) > num_lines:
        seed += otp[-2]
    else:
        seed += otp[-2:]
    
    print(f"Generated seed: {seed}")
    return seed

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Only for testing, don't use in production
    return context

def send_otp_and_counter(secure_sock, otp_hash, counter):
    message = f"{otp_hash}:{counter}"
    print(f"Sending TOTP hash and counter: {message}")
    secure_sock.send(message.encode())
    response = secure_sock.recv(1024).decode()
    return response

def main():
    global client_counter
    poetry_lines = read_poetry_file()
    context = create_ssl_context()
    
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_conn:
            try:
                totp = pyotp.TOTP(base64.b32encode(''.join(poetry_lines).encode()).decode())
                otp = totp.now()
                print(f"Generated OTP: {otp}")
                otp_hash = hash_otp(otp)
                
                response = send_otp_and_counter(secure_conn, otp_hash, client_counter)
                print(f"Server response: {response}")
                
                if response != "OTP Valid":
                    print("OTP validation failed. Exiting.")
                    return

                seed = generate_seed(poetry_lines, otp)
                hotp = pyotp.HOTP(base64.b32encode(seed.encode()).decode())
                current_hotp = hotp.at(client_counter)
                print(f"Generated HOTP: {current_hotp}")

                secure_conn.send(b"Request Credential")

                obfuscated_cred = secure_conn.recv(1024).decode()
                print(f"Received obfuscated credential: {obfuscated_cred}")

                client_counter += 1
                print(f"Updated client counter: {client_counter}")

            except Exception as e:
                print(f"Error during communication: {e}")

if __name__ == "__main__":
    main()