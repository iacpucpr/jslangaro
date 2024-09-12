import socket
import ssl
import pyotp
import hmac
import hashlib
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4443

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def verify_hash(data, received_hash):
    calculated_hash = hashlib.sha256(data.encode()).hexdigest()
    return hmac.compare_digest(calculated_hash, received_hash)

def deobfuscate_credential(obfuscated_cred, otp):
    return ''.join(chr(ord(c) ^ ord(otp[i % len(otp)])) for i, c in enumerate(obfuscated_cred))

def main():
    context = create_ssl_context()
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        # Receber o segredo compartilhado do servidor
        shared_secret = sock.recv(1024).decode()
        
        # Enviar o timestamp atual para o servidor
        current_time = time.time()
        sock.send(str(current_time).encode())
        
        # Gerar OTP usando o segredo compartilhado e o tempo atual
        totp = pyotp.TOTP(shared_secret)
        otp = totp.now()
        otp_hash = hash_otp(otp)

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

        # Verificar hash
        if not verify_hash(obfuscated_cred, received_hash):
            print("Hash inválido")
            return

        # Desofuscar credencial
        credential = deobfuscate_credential(obfuscated_cred, otp)

        # Salvar credencial em arquivo
        with open('credential.txt', 'w') as f:
            f.write(credential)

        print("Credencial recebida e salva com sucesso.")

if __name__ == "__main__":
    main()