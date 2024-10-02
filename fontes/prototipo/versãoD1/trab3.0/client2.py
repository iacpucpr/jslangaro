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
HOST = '192.168.100.130'
PORT = 4443

VAULT_TOKEN = os.getenv('VAULT_TOKEN')
HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))
TEXT_FILE = 'poetry.txt'  # Caminho do arquivo de poesia

if not VAULT_TOKEN:
    print("VAULT_TOKEN não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

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
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    return context

def main():
    global HOTP_COUNTER

    # Extrai a chave secreta da poesia
    SHARED_SECRET = extract_shared_secret_from_text()

    context = create_ssl_context()
    
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_side=False) as secure_conn:
            print(f"Conexão segura estabelecida com {HOST}:{PORT}")

            while True:
                # Gera o HOTP
                otp = generate_hotp(HOTP_COUNTER, SHARED_SECRET)
                otp_hash = hash_otp(otp)

                # Envia o hash do HOTP e o contador para o servidor
                secure_conn.send(otp_hash.encode())
                secure_conn.send(str(HOTP_COUNTER).encode())

                # Receber resposta de ressincronização do servidor
                resync_message = secure_conn.recv(1024).decode()
                print(resync_message)

                # Receber validação do OTP
                response = secure_conn.recv(1024).decode()
                print(response)

                if response == "OTP Valido":
                    # Esperar pela credencial ofuscada do servidor
                    obfuscated_cred = secure_conn.recv(1024).decode()
                    print("Credencial ofuscada recebida:", obfuscated_cred)

                    # Grava a credencial ofuscada em um arquivo
                    with open("obfuscated_credential.txt", "w") as cred_file:
                        cred_file.write(obfuscated_cred)
                    print("Credencial ofuscada salva em 'obfuscated_credential.txt'.")

                # Incrementa o contador após a interação
                HOTP_COUNTER += 1
                os.environ['HOTP_COUNTER'] = str(HOTP_COUNTER)

if __name__ == "__main__":
    main()
