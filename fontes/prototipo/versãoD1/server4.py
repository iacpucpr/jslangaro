import socket
import ssl
import base64
import pyotp
import hmac
import hvac
import hashlib
import os
import logging
from dotenv import load_dotenv

# Configuração do logger para registrar eventos em diferentes níveis (INFO, WARNING, ERROR)
logging.basicConfig(level=logging.INFO)

# Carrega variáveis de ambiente do arquivo .env para proteger segredos sensíveis
load_dotenv()

# Configurações de rede do servidor
HOST = '192.168.100.130'
PORT = 4443

# Obtendo o segredo OTP e o token do Vault das variáveis de ambiente
OTP_SECRET = os.getenv('OTP_SECRET')
VAULT_TOKEN = os.getenv('VAULT_TOKEN')

# Verificação básica para garantir que as variáveis de ambiente essenciais estão definidas
if not OTP_SECRET or not VAULT_TOKEN:
    logging.error("OTP_SECRET ou VAULT_TOKEN não configurados.")
    exit(1)

# URL do Vault para acessar segredos
VAULT_URL = 'http://192.168.100.130:8200'

def generate_otp():
    # Gera um OTP (One-Time Password) usando o segredo armazenado
    totp = pyotp.TOTP(OTP_SECRET)
    return totp.now()

def hash_otp(otp):
    # Gera um hash SHA-256 do OTP para comparações seguras
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    # Cria um contexto SSL configurado para autenticação mútua e verificação de certificados
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Carrega o certificado e a chave do servidor
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    
    # Carrega a CA (Certificate Authority) para verificar certificados do cliente
    context.load_verify_locations(cafile="ca.crt")
    
    # Exige que o cliente apresente um certificado válido (autenticação mútua)
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def get_credential_from_vault():
    # Cria um cliente HVAC para interagir com o Vault
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)

    # Verifica se a autenticação no Vault foi bem-sucedida
    if not client.is_authenticated():
        logging.error("Não foi possível autenticar no Vault")
        return None
   
    try:
        # Lê as credenciais armazenadas no Vault
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['username'], secret['data']['password']
    except hvac.exceptions.VaultError as e:
        logging.error(f"Erro ao acessar o Vault: {e}")
        return None

def obfuscate_credential(credential, otp):
    # Combina o nome de usuário e senha em uma única string
    concatenated_credential = ':'.join(credential)
    
    # Gera um nonce aleatório para derivação de chaves
    nonce = os.urandom(16)
    
    # Deriva uma chave usando PBKDF2 com o OTP e o nonce, e SHA-256 como função de hash
    key = hashlib.pbkdf2_hmac('sha256', otp.encode(), nonce, 100000)
    
    # Ofusca a credencial usando XOR com a chave derivada
    obfuscated_cred = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(concatenated_credential))
    
    # Codifica a credencial ofuscada em Base64 para transporte seguro
    obfuscated_cred_b64 = base64.b64encode(obfuscated_cred.encode()).decode()
    
    # Retorna o nonce e a credencial ofuscada
    return nonce, obfuscated_cred_b64

def generate_hash(data):
    # Gera um hash SHA-256 de qualquer dado fornecido, usado para verificar a integridade
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    context = create_ssl_context()  # Configura o contexto SSL

    # Configura o socket do servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)

        logging.info(f"Servidor iniciado em {HOST}:{PORT}")

        while True:
            # Envolve o socket com SSL para comunicação segura
            with context.wrap_socket(sock, server_side=True) as secure_sock:
                conn, addr = secure_sock.accept()  # Aceita conexões de clientes
                with conn:
                    logging.info(f"Conexão estabelecida com {addr}")

                    # Recebe o hash do OTP do cliente para validação
                    client_otp_hash = conn.recv(1024).decode()

                    # Gera um OTP no servidor e calcula seu hash
                    server_otp = generate_otp()
                    server_otp_hash = hash_otp(server_otp)

                    # Compara o hash do OTP do cliente com o hash gerado pelo servidor
                    if hmac.compare_digest(client_otp_hash, server_otp_hash):
                        conn.send(b"OTP Valido")
                    else:
                        conn.send(b"OTP Invalido")
                        continue  # Encerra a conexão se o OTP for inválido

                    # Espera uma solicitação de credencial do cliente
                    request = conn.recv(1024).decode()
                    if request != "Solicitar Credencial":
                        conn.send(b"Solicitacao Invalida")
                        logging.warning(f"Solicitação inválida de {addr}: {request}")
                        continue

                    # Obtém as credenciais do Vault
                    credential = get_credential_from_vault()
                    if not credential:
                        conn.send(b"Erro ao obter credencial")
                        logging.error(f"Falha ao obter credencial do Vault para {addr}")
                        continue

                    # Ofusca a credencial usando o OTP gerado
                    nonce, obfuscated_cred = obfuscate_credential(credential, server_otp)

                    # Gera um hash da credencial ofuscada para garantir a integridade
                    cred_hash = generate_hash(obfuscated_cred)

                    # Envia a credencial ofuscada, o nonce e o hash ao cliente
                    conn.send(f"{nonce.hex()}|{obfuscated_cred}|{cred_hash}".encode('utf-8'))

                    logging.info("Credencial enviada com sucesso.")

if __name__ == "__main__":
    main()
