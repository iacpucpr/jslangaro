import socket
import ssl
import base64
import pyotp
import hmac
import hvac
import hashlib
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env
load_dotenv()

# Configurações
HOST = '192.168.100.130'
PORT = 4443

# Obtendo o segredo OTP e o token do Vault de variáveis de ambiente
OTP_SECRET = os.getenv('OTP_SECRET')  
VAULT_TOKEN = os.getenv('VAULT_TOKEN')  

if not OTP_SECRET or not VAULT_TOKEN:
    print("OTP_SECRET ou VAULT_TOKEN não configurados. Por favor, configure as variáveis de ambiente.")
    exit(1)

VAULT_URL = 'http://192.168.100.130:8200'

def generate_otp():
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def get_credential_from_vault():
    # Para produção 
    client = hvac.Client(url='http://192.168.100.130:8200', token='hvs.jloguG2rfDlxmkAIHoQH7P6g')

    try:
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['username'], secret['data']['password']
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
            #with context.wrap_socket(sock, server_side=True) as secure_sock:
                conn, addr = sock.accept()
                with conn:
                    print(f"Conexão estabelecida com {addr}")
                    
                    # Receber hash do OTP do cliente
                    client_otp_hash = conn.recv(1024).decode()
                    
                    # Gerar OTP no servidor e comparar hashes
                    server_otp = generate_otp()
                    server_otp_hash = hash_otp(server_otp)
                    
                    if hmac.compare_digest(client_otp_hash, server_otp_hash):
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

