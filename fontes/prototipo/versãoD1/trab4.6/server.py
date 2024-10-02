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
    seed = ""
    
    # Usa os primeiros 8 caracteres da quarta linha
    seed += ''.join(poetry_lines[3][:8])
    
    # Usa o último caractere da primeira linha
    seed += poetry_lines[0][-1]
    
    # Usa o caractere do meio da segunda linha
    middle_index = len(poetry_lines[1]) // 2
    seed += poetry_lines[1][middle_index]
    
    # Usa os dois primeiros caracteres da última linha
    seed += poetry_lines[-1][:2]
    
    # Usa caracteres baseados no OTP
    num_lines = len(poetry_lines)
    otp_value = int(otp[-4:])  # Use os últimos 4 dígitos do OTP
    
    # Seleciona as linhas e caracteres baseados no OTP
    for i in range(4):
        line_index = (otp_value + i) % num_lines
        char_index = (otp_value + i * 2) % len(poetry_lines[line_index])
        seed += poetry_lines[line_index][char_index]
    
    # Adiciona os dois últimos dígitos do OTP
    seed += otp[-2:]
    
    print(f"Generated seed: {seed}")
    return seed

def hash_otp(otp):
    if isinstance(otp, tuple):
        print(f"Error: Expected a string, but received a tuple: {otp}")
        otp = ''.join(otp)  # Converte a tupla em string se for necessário (outra opção seria lançar uma exceção)
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def obfuscate_credential(credential, hotp):
    # Verifique se o valor da credencial é uma tupla e converta para string
    if isinstance(credential, tuple):
        print(f"Error: Expected a string for credential, but got a tuple: {credential}")
        credential = ':'.join(credential)  # Converte a tupla em string

    key = f"{credential}{hotp}"
    
    # Verifique se os valores são strings antes de tentar codificá-los
    if not isinstance(credential, str):
        print(f"Error: Expected a string for credential, but got: {type(credential)}")
        credential = str(credential)
    if not isinstance(hotp, str):
        print(f"Error: Expected a string for hotp, but got: {type(hotp)}")
        hotp = str(hotp)
    
    return hmac.new(key.encode(), credential.encode(), hashlib.sha256).hexdigest()

def get_credential_from_vault():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        print("Não foi possível autenticar no Vault")
        return None
    try:
        secret = client.read('database-glpi/creds/access-db')
        #return secret['data']['username'], secret['data']['password']
        return f"{secret['data']['username']}:{secret['data']['password']}"
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
