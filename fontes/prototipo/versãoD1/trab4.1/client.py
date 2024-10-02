import socket
import ssl
import pyotp
import hmac
import hashlib
import base64

SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

def generate_seed(poetry_lines):
    seed = ''
    seed += ''.join(poetry_lines[3][:16])  # 16 primeiros caracteres da linha 4
    seed += poetry_lines[0][57] if len(poetry_lines[0]) > 57 else 'X'  # Caractere na posição 58
    
    # Gera TOTP baseado no segredo "secret"
    totp = pyotp.TOTP(base64.b32encode('secret'.encode()).decode())
    otp = totp.now()
    
    # Quantidade de linhas no arquivo
    num_lines = len(poetry_lines)
    
    # Se os últimos 2 dígitos do OTP forem maiores que o número de linhas, use o penúltimo dígito
    if int(otp[-2:]) > num_lines:
        seed += otp[-2]
    else:
        seed += otp[-2:]

    return seed

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Apenas para testes, não use em produção
    return context

def load_state(filename='client_state.txt'):
    try:
        with open(filename, 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0

def save_state(counter, filename='client_state.txt'):
    with open(filename, 'w') as f:
        f.write(str(counter))

def main():
    poetry_lines = read_poetry_file()
    seed = generate_seed(poetry_lines)
    counter = load_state()
    
    context = create_ssl_context()
    
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            try:
                # Gera e envia o OTP e o contador
                totp = pyotp.TOTP(base64.b32encode(seed.encode()).decode())
                otp = totp.now()
                otp_hash = hash_otp(otp)
                message = f"{otp_hash}:{counter}"
                print(f"Sending TOTP hash and counter: {message}")
                secure_sock.send(message.encode())

                # Recebe a resposta do servidor
                response = secure_sock.recv(1024).decode()
                print(f"Server response: {response}")
                
                if response == "Counter Out of Sync":
                    print("Counter is out of sync with the server. Please contact the system administrator.")
                    return
                elif response != "OTP Valid":
                    print("OTP validation failed. Exiting.")
                    return

                # Solicita a credencial
                secure_sock.send(b"Request Credential")

                # Recebe a credencial ofuscada
                obfuscated_cred = secure_sock.recv(1024).decode()
                print(f"Received obfuscated credential: {obfuscated_cred}")

                # Atualiza o contador
                counter += 1
                save_state(counter)

            except Exception as e:
                print(f"Error during communication: {e}")

if __name__ == "__main__":
    main()