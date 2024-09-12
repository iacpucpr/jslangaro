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

# Obtendo o token do Vault de variáveis de ambiente
VAULT_TOKEN = os.getenv('VAULT_TOKEN')

if not VAULT_TOKEN:
    print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

VAULT_URL = 'http://192.168.100.130:8200'

# Função para gerar um segredo OTP compartilhado
def generate_shared_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

# Variável global para armazenar o segredo compartilhado
SHARED_SECRET = generate_shared_secret()

def generate_otp():
    totp = pyotp.TOTP(SHARED_SECRET)
    return totp.now()

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

# Mock
class MockVaultClient:
    def read(self, path):
        if path == 'database-glpi/creds/access-db':
            return {
                'data': {
                    'password': 'mock_password_123'
                }
            }
        raise Exception(f"Path not found: {path}")

def get_credential_from_vault():
    client = MockVaultClient()
    
    try:
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['password']
    except Exception as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def obfuscate_credential(credential, otp):
    return ''.join(chr(ord(c) ^ ord(otp[i % len(otp)])) for i, c in enumerate(credential))

def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    if not VAULT_TOKEN:
        print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
        return

    context = create_ssl_context()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print(f"Servidor iniciado em {HOST}:{PORT}")
        
        while True:
            conn, addr = sock.accept()
            with conn:
                print(f"Conexão estabelecida com {addr}")
                
                # Enviar o segredo compartilhado para o cliente
                conn.send(SHARED_SECRET.encode())
                
                # Receber o timestamp do cliente
                client_timestamp = float(conn.recv(1024).decode())
                
                # Calcular a diferença de tempo
                time_diff = time.time() - client_timestamp
                
                # Gerar OTP no servidor
                server_otp = generate_otp()
                
                # Receber hash do OTP do cliente
                client_otp_hash = conn.recv(1024).decode()
                
                # Verificar se o OTP do cliente é válido considerando a diferença de tempo
                if any(hmac.compare_digest(client_otp_hash, hash_otp(pyotp.TOTP(SHARED_SECRET).at(client_timestamp + i))) for i in range(-1, 2)):
                    conn.send(b"OTP Valido")
                else:
                    conn.send(b"OTP Invalido")
                    continue
                
                # Esperar solicitação de credencial
                request = conn.recv(1024).decode()
                if request != "Solicitar Credencial":
                    continue
                
                # Gerar credencial no Vault (mock)
                credential = get_credential_from_vault()
                if not credential:
                    conn.send(b"Erro ao obter credencial")
                    continue
                
                # Ofuscar credencial
                obfuscated_cred = obfuscate_credential(credential, server_otp)
                
                # Gerar hash da credencial ofuscada
                cred_hash = generate_hash(obfuscated_cred)
                
                # Enviar credencial ofuscada e hash
                conn.send(f"{obfuscated_cred}|{cred_hash}".encode())
                
                print("Credencial enviada com sucesso.")

if __name__ == "__main__":
    main()