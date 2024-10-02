import socket
import ssl
import pyotp
import hmac
import hvac
import hashlib
import base64
import time

HOST = '192.168.100.130'
PORT = 4443
TIME_WINDOW = 2

VAULT_URL = 'http://192.168.100.130:8200'
VAULT_TOKEN = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'

# Global counter for the server
server_counter = 0

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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def obfuscate_credential(credential, hotp):
    key = f"{credential}{hotp}"
    return hmac.new(key.encode(), credential.encode(), hashlib.sha256).hexdigest()

def get_credential_from_vault():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        print("Não foi possível autenticar no Vault")
        return None
    try:
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['username'], secret['data']['password']
    except hvac.exceptions.VaultError as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def main():
    global server_counter
    poetry_lines = read_poetry_file()
    context = create_ssl_context()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print(f"Server started on {HOST}:{PORT}")
        
        while True:
            conn, addr = sock.accept()
            with context.wrap_socket(conn, server_side=True) as secure_conn:
                print(f"Secure connection established with {addr}")
                
                try:
                    data = secure_conn.recv(1024).decode().split(':')
                    client_otp_hash, client_counter = data[0], int(data[1])
                    print(f"Received OTP hash from client: {client_otp_hash}")
                    print(f"Received counter from client: {client_counter}")
                    
                    totp = pyotp.TOTP(base64.b32encode(''.join(poetry_lines).encode()).decode())
                    current_otp = totp.now()
                    seed = generate_seed(poetry_lines, current_otp)
                    
                    current_time = int(time.time())
                    valid_window = range(current_time - TIME_WINDOW * 30, current_time + (TIME_WINDOW + 1) * 30, 30)
                    valid_otps = [totp.at(t) for t in valid_window]
                    valid_otp_hashes = [hash_otp(otp) for otp in valid_otps]
                    
                    if client_otp_hash in valid_otp_hashes:
                        secure_conn.send(b"OTP Valid")
                        server_counter = max(server_counter, client_counter)
                    else:
                        secure_conn.send(b"OTP Invalid")
                        continue
                    
                    request = secure_conn.recv(1024).decode()
                    if request != "Request Credential":
                        continue
                    
                    hotp = pyotp.HOTP(base64.b32encode(seed.encode()).decode())
                    current_hotp = hotp.at(server_counter)
                    
                    credential = get_credential_from_vault()
                    concatenated_credential = ':'.join(credential)
                    obfuscated_cred = obfuscate_credential(credential, current_hotp)
                    
                    print(f"Original credential: {credential}")
                    print(f"Obfuscated credential: {obfuscated_cred}")
                    
                    secure_conn.send(obfuscated_cred.encode())
                    
                    server_counter += 1
                    print(f"Updated server counter: {server_counter}")
                    
                except Exception as e:
                    print(f"Error during communication: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()