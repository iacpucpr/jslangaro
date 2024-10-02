import socket
import ssl
import base64
import pyotp
import hmac
import hvac
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
TEXT_FILE = 'poetry.txt'  # Caminho do arquivo de poesia

if not VAULT_TOKEN:
    print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

VAULT_URL = 'http://192.168.100.130:8200'

def extract_shared_secret_from_text():
    """Extrai uma chave secreta a partir do texto da poesia e outros valores dinâmicos."""
    with open(TEXT_FILE, 'r') as file:
        lines = file.readlines()
    poetry_part = lines[0].strip()[:16]  # Extrair os primeiros 16 caracteres da primeira linha

    # Variáveis dinâmicas
    timestamp = str(int(time.time()))
    hostname = socket.gethostname()
    username = os.getlogin()

    # Combinando todos os elementos para gerar a chave secreta
    combined = poetry_part + timestamp + hostname + username
    secret_key = hashlib.sha256(combined.encode()).hexdigest()

    return secret_key[:16]

def generate_hotp(counter, secret_key):
    hotp = pyotp.HOTP(secret_key)
    return hotp.at(counter)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("server.crt")
    return context

def obfuscate_credential(credential, secret_key):
    """Ofusca a credencial usando HOTP, HMAC e Base64."""
    hotp = generate_hotp(HOTP_COUNTER, secret_key)
    hmac_hash = hmac.new(secret_key.encode(), credential.encode() + hotp.encode(), hashlib.sha256).hexdigest()
    combined = f"{credential}|{hmac_hash}"
    return base64.b64encode(combined.encode()).decode()

def desobfuscate_credential(obfuscated_cred, secret_key):
    """Desofusca a credencial usando HOTP e HMAC."""
    decoded = base64.b64decode(obfuscated_cred).decode()
    credential, hmac_hash = decoded.split('|')
    
    # Verifica a validade do HMAC
    hotp = generate_hotp(HOTP_COUNTER, secret_key)
    expected_hmac_hash = hmac.new(secret_key.encode(), credential.encode() + hotp.encode(), hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(expected_hmac_hash, hmac_hash):
        return credential
    else:
        raise ValueError("HMAC inválido! Credencial não pode ser desofuscada.")

def main():
    # Extrai a chave secreta da poesia
    SHARED_SECRET = extract_shared_secret_from_text()

    context = create_ssl_context()
    
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as secure_sock:
            print(f"Conexão segura estabelecida com o servidor {HOST}:{PORT}")

            # Enviar contador para o servidor
            HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))
            secure_sock.send(str(HOTP_COUNTER).encode())

            # Gerar HOTP e HMAC
            otp = generate_hotp(HOTP_COUNTER, SHARED_SECRET)
            otp_hash = hash_otp(otp)

            # Enviar hash do HOTP para o servidor
            secure_sock.send(otp_hash.encode())
            print("Hash do OTP enviado para o servidor.")

            # Esperar resposta do servidor
            server_response = secure_sock.recv(1024).decode()
            print(f"Resposta do servidor: {server_response}")

            if server_response == "OTP Valido":
                # Solicitar credencial
                secure_sock.send(b"Solicitar Credencial")

                # Receber credencial ofuscada do servidor
                obfuscated_cred = secure_sock.recv(1024).decode()
                print("Credencial ofuscada recebida do servidor.")

                # Desofuscar a credencial
                try:
                    credential = desobfuscate_credential(obfuscated_cred, SHARED_SECRET)
                    print(f"Credencial desofuscada: {credential}")
                except ValueError as e:
                    print(str(e))
            else:
                print("Falha na validação do OTP. Não será possível solicitar a credencial.")

if __name__ == "__main__":
    main()
