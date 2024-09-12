import socket
import ssl
import pyotp
import hmac
import hashlib
import os
from dotenv import load_dotenv

# Carrega  .env
load_dotenv()

SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443

OTP_SECRET = os.getenv('OTP_SECRET')  

if not OTP_SECRET:
    print("OTP_SECRET não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

def generate_otp():
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def deobfuscate_credential(obfuscated_cred, otp):
    #return ''.join(chr(ord(c) ^ ord(otp[i % len(otp)])) for i, c in enumerate(obfuscated_cred))
    
    # Supondo que o OTP seja usado diretamente como a chave para XOR
    decoded_cred = ''.join(chr(ord(c) ^ ord(otp[i % len(otp)])) for i, c in enumerate(obfuscated_cred))

    # Verificar se a credencial contém o caractere ':'
    if ':' not in decoded_cred:
        raise ValueError("A credencial decodificada não contém o caractere ':' para separar usuário e senha")

    # Dividir o resultado em usuário e senha
    username, password = decoded_cred.split(':', 1)
    return username, password 

def verify_hash(data, received_hash):
    calculated_hash = hashlib.sha256(data.encode()).hexdigest()
    return hmac.compare_digest(calculated_hash, received_hash)

def main():
    otp = generate_otp()
    otp_hash = hash_otp(otp)

    context = create_ssl_context()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        #with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            # Enviar hash do OTP
            sock.send(otp_hash.encode())

            # Receber resposta do servidor
            response = sock.recv(1024).decode()
            if response != "OTP Valido":
                print(f"Falha na validação do OTP: {response}")
                return

            # Solicitar credencial
            sock.send(b"Solicitar Credencial")

            # Receber credencial ofuscada e hash
            response = sock.recv(4096).decode()
            if response == "Erro ao obter credencial":
                print("O servidor não pôde fornecer a credencial")
                return

            data = response.split('|')
            if len(data) != 2:
                print("Formato de resposta inválido")
                return

            obfuscated_cred, received_hash = data

            # Exibir credencial ofuscada
            print(f"Credencial ofuscada recebida: {obfuscated_cred}")

            # Verificar hash
            if not verify_hash(obfuscated_cred, received_hash):
                print("Hash inválido")
                return
            
            try:
                # Desofuscar credencial
                #credential = deobfuscate_credential(obfuscated_cred, otp)
                username, password = deobfuscate_credential(obfuscated_cred, otp)

                # Exibir credencial desofuscada
                #print(f"Credencial desofuscada: {credential}")
                print(f"Usuário desofuscado: {username}")
                print(f"Senha desofuscada: {password}")

                # Salvar credencial em arquivo
                with open('credential.txt', 'w') as f:
                    f.write(f"Usuário: {username}\nSenha: {password}")

                print("Credencial recebida e salva com sucesso.")
            except ValueError as e:
                print(f"Erro ao desofuscar credencial: {e}")

if __name__ == "__main__":
    main()
