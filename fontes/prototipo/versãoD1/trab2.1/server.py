import socket
import ssl
import base64
import pyotp
import hmac
import hashlib
import os
import time
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env
load_dotenv()

# Configurações
HOST = '127.0.0.1'
PORT = 4443

VAULT_TOKEN = os.getenv('VAULT_TOKEN')
HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))

if not VAULT_TOKEN:
    print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

VAULT_URL = 'http://192.168.100.130:8200'

def generate_shared_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

SHARED_SECRET = generate_shared_secret()

def generate_otp():
    totp = pyotp.TOTP(SHARED_SECRET)
    return totp.now()

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Certificado e chave privada do servidor
    return context

class MockVaultClient:
    def read(self, path):
        if path == 'database-glpi/creds/access-db':
            return {
                'data': {
                    'username': 'mock_username',
                    'password': 'mock_password_123'
                }
            }
        raise Exception(f"Path not found: {path}")

def get_credential_from_vault():
    client = MockVaultClient()
    try:
        secret = client.read('database-glpi/creds/access-db')
        return f"{secret['data']['username']}:{secret['data']['password']}"
    except Exception as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def obfuscate_credential(credential):
    return base64.b64encode(credential.encode()).decode()

def generate_hash(data, secret_key, counter):
    hotp = pyotp.HOTP(secret_key)
    otp = hotp.at(counter)
    hmac_hash = hmac.new(secret_key.encode(), data.encode() + otp.encode(), hashlib.sha256).hexdigest()
    return hmac_hash

def main():
    global HOTP_COUNTER

    if not VAULT_TOKEN:
        print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
        return

    context = create_ssl_context()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permite reutilização imediata da porta
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print(f"Servidor iniciado em {HOST}:{PORT}")
        
        while True:
            conn, addr = sock.accept()
            with context.wrap_socket(conn, server_side=True) as secure_conn:  # Usando SSL
                print(f"Conexão segura estabelecida com {addr}")
                
                try:
                    # Enviar o segredo compartilhado para o cliente
                    secure_conn.send(SHARED_SECRET.encode())
                    
                    # Receber o timestamp do cliente
                    client_timestamp = float(secure_conn.recv(1024).decode())
                    
                    # Calcular a diferença de tempo
                    time_diff = time.time() - client_timestamp
                    
                    # Gerar OTP no servidor
                    server_otp = generate_otp()
                    
                    # Receber hash do OTP do cliente
                    client_otp_hash = secure_conn.recv(1024).decode()
                    
                    # Verificar se o OTP do cliente é válido considerando a diferença de tempo
                    if any(hmac.compare_digest(client_otp_hash, hash_otp(pyotp.TOTP(SHARED_SECRET).at(client_timestamp + i))) for i in range(-1, 2)):
                        secure_conn.send(b"OTP Valido")
                    else:
                        secure_conn.send(b"OTP Invalido")
                        continue
                    
                    # Esperar solicitação de credencial
                    request = secure_conn.recv(1024).decode()
                    if request != "Solicitar Credencial":
                        continue
                    
                    # Gerar credencial no Vault (mock)
                    credential = get_credential_from_vault()
                    if not credential:
                        secure_conn.send(b"Erro ao obter credencial")
                        continue
                    
                    # Ofuscar credencial
                    obfuscated_cred = obfuscate_credential(credential)
                    
                    # Gerar hash da credencial ofuscada usando HMAC + HOTP
                    cred_hash = generate_hash(obfuscated_cred, SHARED_SECRET, HOTP_COUNTER)
                    
                    # Incrementar o contador HOTP
                    HOTP_COUNTER += 1
                    os.environ['HOTP_COUNTER'] = str(HOTP_COUNTER)
                    
                    # Enviar credencial ofuscada e hash
                    secure_conn.send(f"{obfuscated_cred}|{cred_hash}".encode())
                    
                    print("Credencial enviada com sucesso.")
                
                except Exception as e:
                    print(f"Erro durante a comunicação: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()