import socket
import ssl
import pyotp
import hmac
import hashlib
import time
import base64
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env
load_dotenv()

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4443

HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")  # Certificado do servidor
    context.check_hostname = False
    return context

def verify_hash(data, received_hash, secret_key, counter):
    hotp = pyotp.HOTP(secret_key)
    otp = hotp.at(counter)
    calculated_hash = hmac.new(secret_key.encode(), data.encode() + otp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_hash, received_hash)

def deobfuscate_credential(obfuscated_cred):
    return base64.b64decode(obfuscated_cred.encode()).decode()

def main():
    global HOTP_COUNTER
    
    context = create_ssl_context()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            # Receber o segredo compartilhado do servidor
            shared_secret = secure_sock.recv(1024).decode()
            
            # Enviar o timestamp atual para o servidor
            current_time = time.time()
            secure_sock.send(str(current_time).encode())
            
            # Gerar OTP usando o segredo compartilhado e o tempo atual
            totp = pyotp.TOTP(shared_secret)
            otp = totp.now()
            otp_hash = hash_otp(otp)

            # Enviar hash do OTP
            secure_sock.send(otp_hash.encode())

            # Receber resposta do servidor
            response = secure_sock.recv(1024).decode()
            if response != "OTP Valido":
                print(f"Falha na validação do OTP: {response}")
                return

            # Solicitar credencial
            secure_sock.send(b"Solicitar Credencial")

            # Receber credencial ofuscada e hash
            response = secure_sock.recv(4096).decode()
            if response == "Erro ao obter credencial":
                print("O servidor não pôde fornecer a credencial")
                return

            data = response.split('|')
            if len(data) != 2:
                print("Formato de resposta inválido")
                return

            obfuscated_cred, received_hash = data

            # Verificar hash usando HMAC + HOTP
            if not verify_hash(obfuscated_cred, received_hash, shared_secret, HOTP_COUNTER):
                print("Hash inválido")
                return

            # Incrementar o contador HOTP
            HOTP_COUNTER += 1
            os.environ['HOTP_COUNTER'] = str(HOTP_COUNTER)

            # Desofuscar credencial
            credential = deobfuscate_credential(obfuscated_cred)

            # Salvar credencial em arquivo
            with open('credential.txt', 'w') as f:
                f.write(credential)

            print("Credencial recebida e salva com sucesso.")

if __name__ == "__main__":
    main()
