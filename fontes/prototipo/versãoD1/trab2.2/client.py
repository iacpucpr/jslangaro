import socket
import ssl
import pyotp
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env
load_dotenv()

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4443

HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))
SHARED_SECRET = os.getenv('SHARED_SECRET')

if not SHARED_SECRET:
    print("SHARED_SECRET não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

def generate_hotp(counter):
    hotp = pyotp.HOTP(SHARED_SECRET)
    return hotp.at(counter)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    return context

def verify_hash(data, received_hash, secret_key, counter):
    hotp = pyotp.HOTP(secret_key)
    otp = hotp.at(counter)
    calculated_hash = hmac.new(secret_key.encode(), data.encode() + otp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_hash, received_hash)

def deobfuscate_credential(obfuscated_cred):
    return base64.b64decode(obfuscated_cred.encode()).decode()

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
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            try:
                for i in range(5):  # Tenta 5 vezes
                    current_counter = HOTP_COUNTER + i
                    otp = generate_hotp(current_counter)
                    otp_hash = hash_otp(otp)

                    print(f"Tentativa {i+1}: Enviando OTP hash para o contador: {current_counter}")

                    secure_sock.send(otp_hash.encode())

                    response = secure_sock.recv(1024).decode()
                    print(f"Resposta do servidor: {response}")

                    if response == "OTP Valido":
                        print("OTP validado com sucesso!")
                        update_hotp_counter(current_counter + 1)
                        break
                    else:
                        print(f"Falha na validação do OTP: {response}")
                        if i == 4:  # Última tentativa
                            print("Todas as tentativas falharam. Encerrando.")
                            return
                
                # Solicitar credencial
                secure_sock.send(b"Solicitar Credencial")
                response = secure_sock.recv(4096).decode()
                
                if response == "Erro ao obter credencial":
                    print("O servidor não pôde fornecer a credencial")
                    return

                data = response.split('|')
                if len(data) != 2:
                    print("Formato de resposta inválido")
                    return

                obfuscated_cred, received_hash = data
                if not verify_hash(obfuscated_cred, received_hash, SHARED_SECRET, HOTP_COUNTER):
                    print("Hash inválido")
                    return

                deobfuscated_cred = deobfuscate_credential(obfuscated_cred)
                print("Credencial ofuscada:", obfuscated_cred)
                print("Credencial desofuscada:", deobfuscated_cred)

                with open('credential.txt', 'w') as f:
                    f.write(f"Ofuscada: {obfuscated_cred}\n")
                    f.write(f"Desofuscada: {deobfuscated_cred}")

                print("Credenciais salvas com sucesso em 'credential.txt'.")
            
            except Exception as e:
                print(f"Erro durante a comunicação: {e}")
            finally:
                secure_sock.close()

if __name__ == "__main__":
    print(f"HOTP_COUNTER inicial: {HOTP_COUNTER}")
    main()