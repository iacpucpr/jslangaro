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
MAX_COUNTER_DIFFERENCE = 20  # Diferença máxima aceitável entre contadores
TIME_WINDOW = 2  # Allow 1 step before and after the current time

VAULT_URL = 'http://192.168.100.130:8200'
VAULT_TOKEN = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'

# Global counter
server_counter = 0

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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def obfuscate_credential(credential, seed, counter):
    key = f"{seed}{credential}{counter}"
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

def save_credential_comparison(original, obfuscated, filename='credential.txt'):
    with open(filename, 'w') as f:
        f.write(f"Original: {original}\n")
        f.write(f"Obfuscada: {obfuscated}\n")

def main():
    global server_counter
    
    poetry_lines = read_poetry_file()
    seed = generate_seed(poetry_lines)
    
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
                    # Recebe o hash do OTP e o contador do cliente
                    data = secure_conn.recv(1024).decode().split(':')
                    client_otp_hash, client_counter = data[0], int(data[1])
                    print(f"Received OTP hash from client: {client_otp_hash}")
                    print(f"Received counter from client: {client_counter}")
                    
                    # Gera o OTP do servidor e compara
                    totp = pyotp.TOTP(base64.b32encode(seed.encode()).decode())
                    current_time = int(time.time())
                    
                    valid_window = range(current_time - TIME_WINDOW * 30, current_time + (TIME_WINDOW + 1) * 30, 30)
                    valid_otps = [totp.at(t) for t in valid_window]
                    valid_otp_hashes = [hash_otp(otp) for otp in valid_otps]
                    
                    # Verifica a sincronização do contador
                    counter_diff = abs(server_counter - client_counter)
                    if counter_diff > MAX_COUNTER_DIFFERENCE:
                        secure_conn.send(b"Counter Out of Sync")
                        secure_conn.send(str(server_counter).encode())  # Enviar o contador atualizado
                        continue
                    
                    if client_otp_hash in valid_otp_hashes:
                        secure_conn.send(b"OTP Valid")
                        server_counter = max(server_counter, client_counter)  # Sincroniza o contador
                    else:
                        secure_conn.send(b"OTP Invalid")
                        continue
                    
                    # Recebe a solicitação do cliente
                    request = secure_conn.recv(1024).decode()
                    if request != "Request Credential":
                        continue
                    
                    # Obtém e ofusca a credencial
                    credential = get_credential_from_vault()
                    obfuscated_cred = obfuscate_credential(credential, seed, server_counter)
                    
                    # Salva a comparação em credential.txt
                    save_credential_comparison(credential, obfuscated_cred)
                    
                    # Envia a credencial ofuscada
                    secure_conn.send(obfuscated_cred.encode())
                    
                    # Atualiza o contador
                    server_counter += 1
                    
                except Exception as e:
                    print(f"Error during communication: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()
