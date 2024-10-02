import socket
import ssl
import pyotp
import hashlib
import base64
import time

SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443

# Global counter
client_counter = 0

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

def generate_seed(poetry_lines):
    seed = ''.join(poetry_lines[3][:16])  # 16 primeiros caracteres da linha 4
    if len(poetry_lines[0]) > 57:
        seed += poetry_lines[0][57]  # Caractere na posição 58
    
    print(f"Generated seed: {seed}")  # Log the generated seed
    return seed

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Apenas para testes, não use em produção
    return context

def send_otp_and_counter(secure_sock, otp_hash, counter):
    message = f"{otp_hash}:{counter}"
    print(f"Sending TOTP hash and counter: {message}")
    
    # Certifique-se de que 'message' está codificado como bytes
    secure_sock.send(message.encode())
    
    # Recebe a resposta e decodifica de bytes para string
    response = secure_sock.recv(1024).decode()
    return response

def main():
    global client_counter
    
    poetry_lines = read_poetry_file()
    seed = generate_seed(poetry_lines)
    
    context = create_ssl_context()
    
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            try:
                # Gera o OTP
                totp = pyotp.TOTP(base64.b32encode(seed.encode()).decode())
                otp = totp.now()
                print(f"Generated OTP: {otp}")  # Log the generated OTP
                otp_hash = hash_otp(otp)
                
                # Tenta sincronizar o contador
                max_attempts = 5
                for attempt in range(max_attempts):
                    response = send_otp_and_counter(secure_sock, otp_hash, client_counter)
                    print(f"Server response: {response}")
                    
                    if response == "OTP Valid":
                        break
                    elif response == "Counter Out of Sync":
                        print(f"Attempt {attempt + 1}: Counter out of sync. Synchronizing with server.")
                        server_counter = int(secure_sock.recv(1024).decode())  # Receber o novo contador
                        client_counter = server_counter  # Sincronizar com o contador do servidor
                        print(f"Synchronized client counter to: {client_counter}")
                    else:
                        print("OTP validation failed. Exiting.")
                        return
                
                if attempt == max_attempts - 1 and response != "OTP Valid":
                    print("Failed to synchronize counter after maximum attempts. Exiting.")
                    return

                # Solicita a credencial
                secure_sock.send(b"Request Credential")

                # Recebe a credencial ofuscada
                obfuscated_cred = secure_sock.recv(1024).decode()
                print(f"Received obfuscated credential: {obfuscated_cred}")

                # Atualiza o contador
                client_counter += 1
                print(f"Updated client counter: {client_counter}")

            except Exception as e:
                print(f"Error during communication: {e}")

if __name__ == "__main__":
    main()
