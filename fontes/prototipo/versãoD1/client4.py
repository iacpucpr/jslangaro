import socket
import ssl
import pyotp
import hmac
import hashlib
import os
import logging
from dotenv import load_dotenv

# Configuração do logger para registrar eventos em diferentes níveis (INFO, WARNING, ERROR)
logging.basicConfig(level=logging.INFO)

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do servidor
SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443

# Obtendo o segredo OTP da variável de ambiente
OTP_SECRET = os.getenv('OTP_SECRET')

# Verificação básica para garantir que a variável de ambiente essencial está definida
if not OTP_SECRET:
    logging.error("OTP_SECRET não configurado. Por favor, configure a variável de ambiente.")
    exit(1)

def generate_otp():
    # Gera um OTP (One-Time Password) usando o segredo armazenado
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def hash_otp(otp):
    # Gera um hash SHA-256 do OTP para comparações seguras
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    # Cria um contexto SSL configurado para autenticação mútua e verificação de certificados
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Carrega o certificado e a chave do cliente
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    
    # Carrega a CA (Certificate Authority) para verificar o certificado do servidor
    context.load_verify_locations(cafile="ca.crt")
    
    # Exige a verificação do certificado do servidor
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def deobfuscate_credential(obfuscated_cred, otp, nonce):
    # Deriva uma chave usando PBKDF2 com o OTP e o nonce, e SHA-256 como função de hash
    key = hashlib.pbkdf2_hmac('sha256', otp.encode(), nonce, 100000)
    
    # Decodifica a credencial ofuscada de Base64
    obfuscated_cred_bytes = base64.b64decode(obfuscated_cred.encode())
    
    # Desofusca a credencial usando XOR com a chave derivada
    return ''.join(chr(b ^ key[i % len(key)]) for i, b in enumerate(obfuscated_cred_bytes))

def verify_hash(data, received_hash):
    # Gera um hash SHA-256 de qualquer dado fornecido para comparar com o hash recebido
    calculated_hash = hashlib.sha256(data.encode()).hexdigest()
    return hmac.compare_digest(calculated_hash, received_hash)

def main():
    otp = generate_otp()  # Gera um OTP único
    otp_hash = hash_otp(otp)  # Gera o hash do OTP

    context = create_ssl_context()  # Configura o contexto SSL

    # Estabelece uma conexão segura com o servidor
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            # Envia o hash do OTP ao servidor para validação
            secure_sock.send(otp_hash.encode())

            # Recebe a resposta do servidor sobre a validade do OTP
            response = secure_sock.recv(1024).decode()
            if response != "OTP Valido":
                logging.error(f"Falha na validação do OTP: {response}")
                return

            # Solicita a credencial ao servidor
            secure_sock.send(b"Solicitar Credencial")

            # Recebe a credencial ofuscada, o nonce e o hash
            response = secure_sock.recv(4096).decode()
            if response == "Erro ao obter credencial":
                logging.error("O servidor não pôde fornecer a credencial.")
                return

            data = response.split('|')
            if len(data) != 3:
                logging.error("Formato de resposta inválido.")
                return

            nonce_hex, obfuscated_cred, received_hash = data

            # Converte o nonce de volta para bytes
            nonce = bytes.fromhex(nonce_hex)

            # Verifica a integridade da credencial ofuscada com o hash recebido
            if not verify_hash(obfuscated_cred, received_hash):
                logging.error("Hash inválido.")
                return

            # Desofusca a credencial usando o OTP e o nonce
            credential = deobfuscate_credential(obfuscated_cred, otp, nonce)

            # Salva a credencial em um arquivo
            with open('credential.txt', 'w') as f:
                f.write(credential)

            logging.info("Credencial recebida e salva com sucesso.")

if __name__ == "__main__":
    main()
