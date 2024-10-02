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
    seed = ""
    
    # Use os primeiros 8 caracteres da quarta linha
    seed += ''.join(poetry_lines[3][:8])
    
    # Use o último caractere da primeira linha
    seed += poetry_lines[0][-1]
    
    # Use o caractere do meio da segunda linha
    middle_index = len(poetry_lines[1]) // 2
    seed += poetry_lines[1][middle_index]
    
    # Use os dois primeiros caracteres da última linha
    seed += poetry_lines[-1][:2]
    
    # Use caracteres baseados no OTP
    num_lines = len(poetry_lines)
    otp_value = int(otp[-4:])  # Use os últimos 4 dígitos do OTP
    
    # Selecione linhas e caracteres baseados no OTP
    for i in range(4):
        line_index = (otp_value + i) % num_lines
        char_index = (otp_value + i * 2) % len(poetry_lines[line_index])
        seed += poetry_lines[line_index][char_index]
    
    # Adicione os dois últimos dígitos do OTP
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

def send_otp_and_counter(secure_conn, otp_hash, counter):
    message = f"{otp_hash}:{counter}"
    print(f"Sending TOTP hash and counter: {message}")
    secure_conn.send(message.encode())
    response = secure_conn.recv(1024).decode()
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