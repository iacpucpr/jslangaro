import socket
import ssl
import pyotp
import hmac
import hvac
import hashlib
import base64

HOST = '192.168.100.130'
PORT = 4443
MAX_COUNTER_DIFFERENCE = 5  # Diferença máxima aceitável entre contadores

VAULT_URL = 'http://192.168.100.130:8200'
VAULT_TOKEN = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'

# Contador global em memória
server_counter = 0

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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def obfuscate_credential(credential, seed, counter):
    # Ofusca a credencial com seed + credencial + contador usando HMAC SHA256
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
        print(f"Initial server counter: {server_counter}")
        
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
                    print(f"Current server counter: {server_counter}")
                    
                    # Gera o OTP do servidor e compara
                    totp = pyotp.TOTP(base64.b32encode(seed.encode()).decode())
                    server_otp = totp.now()
                    server_otp_hash = hash_otp(server_otp)
                    
                    # Verifica a sincronização do contador
                    counter_diff = abs(server_counter - client_counter)
                    if counter_diff > MAX_COUNTER_DIFFERENCE:
                        secure_conn.send(b"Counter Out of Sync")
                        print(f"Counter out of sync. Server: {server_counter}, Client: {client_counter}")
                        continue
                    
                    if hmac.compare_digest(client_otp_hash, server_otp_hash):
                        secure_conn.send(b"OTP Valid")
                        print("OTP validated successfully")
                    else:
                        secure_conn.send(b"OTP Invalid")
                        print("OTP validation failed")
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
                    print("Credential sent successfully.")
                    
                    # Atualiza o contador
                    server_counter += 1
                    print(f"Updated server counter: {server_counter}")
                    
                except Exception as e:
                    print(f"Error during communication: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()