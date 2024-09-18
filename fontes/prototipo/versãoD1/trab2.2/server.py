import socket
import ssl
import base64
import pyotp
import hmac
import hashlib
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env
load_dotenv()

# Configurações
HOST = '127.0.0.1'
PORT = 4443

VAULT_TOKEN = os.getenv('VAULT_TOKEN')
HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))
SHARED_SECRET = os.getenv('SHARED_SECRET')

if not VAULT_TOKEN or not SHARED_SECRET:
    print("VAULT_TOKEN ou SHARED_SECRET não configurado. Por favor, configure as variáveis de ambiente.")
    exit(1)

VAULT_URL = 'http://192.168.100.130:8200'

def generate_hotp(counter):
    hotp = pyotp.HOTP(SHARED_SECRET)
    return hotp.at(counter)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
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

def validate_hotp(client_otp_hash, look_ahead=10):
    global HOTP_COUNTER
    print(f"Validando HOTP. Contador atual do servidor: {HOTP_COUNTER}")
    for i in range(look_ahead):
        server_otp = generate_hotp(HOTP_COUNTER + i)
        server_otp_hash = hash_otp(server_otp)
        print(f"Tentativa {i+1}: Comparando hash do cliente com hash do servidor (contador: {HOTP_COUNTER + i})")
        if hmac.compare_digest(client_otp_hash, server_otp_hash):
            HOTP_COUNTER = HOTP_COUNTER + i + 1  # Incrementa o contador após sucesso
            print(f"OTP válido encontrado. Novo contador: {HOTP_COUNTER}")
            update_hotp_counter(HOTP_COUNTER)
            return True
    print("Nenhum OTP válido encontrado dentro da janela de tolerância.")
    return False

def update_hotp_counter(new_value):
    global HOTP_COUNTER
    HOTP_COUNTER = new_value
    os.environ['HOTP_COUNTER'] = str(HOTP_COUNTER)
    with open('.env', 'r') as file:
        env_lines = file.readlines()
    with open('.env', 'w') as file:
        for line in env_lines:
            if line.startswith('HOTP_COUNTER='):
                file.write(f'HOTP_COUNTER={HOTP_COUNTER}\n')
            else:
                file.write(line)
    print(f"HOTP_COUNTER atualizado para {HOTP_COUNTER}")

def main():
    global HOTP_COUNTER

    context = create_ssl_context()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print(f"Servidor iniciado em {HOST}:{PORT}")
        print(f"HOTP_COUNTER inicial do servidor: {HOTP_COUNTER}")
        
        while True:
            conn, addr = sock.accept()
            with context.wrap_socket(conn, server_side=True) as secure_conn:
                print(f"Conexão segura estabelecida com {addr}")
                
                try:
                    # Receber hash do HOTP do cliente
                    client_otp_hash = secure_conn.recv(1024).decode()
                    print(f"Hash do OTP recebido do cliente: {client_otp_hash}")
                    
                    # Verificar se o HOTP do cliente é válido
                    if validate_hotp(client_otp_hash):
                        secure_conn.send(b"OTP Valido")
                        print("OTP validado com sucesso")
                    else:
                        secure_conn.send(b"OTP Invalido")
                        print("Falha na validação do OTP")
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
                    
                    # Enviar credencial ofuscada e hash
                    secure_conn.send(f"{obfuscated_cred}|{cred_hash}".encode())
                    
                    print("Credencial enviada com sucesso.")
                    
                    # Persistir o novo valor do contador
                    os.environ['HOTP_COUNTER'] = str(HOTP_COUNTER)
                    with open('.env', 'r') as file:
                        env_lines = file.readlines()
                    with open('.env', 'w') as file:
                        for line in env_lines:
                            if line.startswith('HOTP_COUNTER='):
                                file.write(f'HOTP_COUNTER={HOTP_COUNTER}\n')
                            else:
                                file.write(line)
                
                except Exception as e:
                    print(f"Erro durante a comunicação: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()