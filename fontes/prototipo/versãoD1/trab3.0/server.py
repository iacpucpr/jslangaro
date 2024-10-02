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
HOTP_COUNTER = int(os.getenv('HOTP_COUNTER', '0'))
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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def get_credential_from_vault():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        print("Não foi possível autenticar no Vault")
        return None
    
    try:
        secret = client.read('database-glpi/creds/access-db')
        return f"{secret['data']['username']}:{secret['data']['password']}"
    except Exception as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def obfuscate_credential(credential, secret_key):
    """Ofusca a credencial usando HOTP, HMAC e Base64."""
    hotp = generate_hotp(HOTP_COUNTER, secret_key)
    hmac_hash = hmac.new(secret_key.encode(), credential.encode() + hotp.encode(), hashlib.sha256).hexdigest()
    combined = f"{credential}|{hmac_hash}"
    return base64.b64encode(combined.encode()).decode()

def generate_hash(data, secret_key, counter):
    hotp = generate_hotp(counter, secret_key)
    hmac_hash = hmac.new(secret_key.encode(), data.encode() + hotp.encode(), hashlib.sha256).hexdigest()
    return hmac_hash

def validate_hotp(client_otp_hash, secret_key, look_ahead=10):
    global HOTP_COUNTER
    print(f"Validando HOTP. Contador atual do servidor: {HOTP_COUNTER}")
    for i in range(look_ahead):
        server_otp = generate_hotp(HOTP_COUNTER + i, secret_key)
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
    
    # Atualiza o .env
    with open('.env', 'r') as file:
        env_lines = file.readlines()
    with open('.env', 'w') as file:
        for line in env_lines:
            if line.startswith('HOTP_COUNTER='):
                file.write(f'HOTP_COUNTER={HOTP_COUNTER}\n')
            else:
                file.write(line)
    print(f"HOTP_COUNTER atualizado para {HOTP_COUNTER}")
    
    # Persistindo o contador no arquivo de poesia
    with open(TEXT_FILE, 'r+') as file:
        lines = file.readlines()
        lines[1] = f"{HOTP_COUNTER}\n"  # Armazenar o contador na segunda linha
        file.seek(0)
        file.writelines(lines)

def resynchronize(client_counter):
    """Ressincroniza o contador do servidor com o do cliente."""
    global HOTP_COUNTER
    if client_counter > HOTP_COUNTER:
        print(f"Ressincronizando... O contador do cliente ({client_counter}) é maior que o do servidor ({HOTP_COUNTER}).")
        HOTP_COUNTER = client_counter
        update_hotp_counter(HOTP_COUNTER)
        return True
    return False

def main():
    global HOTP_COUNTER

    # Extrai a chave secreta da poesia
    SHARED_SECRET = extract_shared_secret_from_text()

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

                    # Receber contador do cliente
                    client_counter = int(secure_conn.recv(1024).decode())
                    print(f"Contador do cliente recebido: {client_counter}")

                    # Ressincronizar se necessário
                    if resynchronize(client_counter):
                        secure_conn.send(b"Ressincronizado com sucesso.")
                    else:
                        secure_conn.send(b"Sem necessidade de ressincronização.")
                    
                    # Validar o HOTP do cliente
                    if validate_hotp(client_otp_hash, SHARED_SECRET):
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
                    
                    # Ofuscar credencial usando HOTP, HMAC e Base64
                    obfuscated_cred = obfuscate_credential(credential, SHARED_SECRET)
                    
                    # Enviar credencial ofuscada
                    secure_conn.send(obfuscated_cred.encode())
                    
                    print("Credencial ofuscada enviada com sucesso.")
                
                except Exception as e:
                    print(f"Erro durante a comunicação: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()
