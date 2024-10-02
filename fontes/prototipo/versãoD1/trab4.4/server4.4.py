import socket
import ssl
import pyotp
import hmac
import hvac
import hashlib
import base64

1) PyOTP nos dois lados + hash
valida no servidor o has 
(pegar da semente com base no poema?)

2) Montar a generate_seed
Logica que tem hoje 2 valores / linhas
+ procedimento abaixo (OTP será o do PyOTP)
# Quantidade de linhas no arquivo
    num_lines = len(poetry_lines)
    
    # Se os últimos 2 dígitos do OTP forem maiores que o número de linhas, use o penúltimo dígito
    if int(otp[-2:]) > num_lines:
        seed += otp[-2]
    else:
        seed += otp[-2:]

3) Gerar o HTOP -> SEED + contador

4) Pegar a credencial (função nao altera)

5) Ofuscacao da credencial
Usar a credencial + HOTP
Fazer o HMAC com o sha256
key = f"{credential}{HOTP}"
return hmac.new(key.encode(), credential.encode(), hashlib.sha256).hexdigest()

6) print dos resultados para validacao
geração do txt final com o valor da credential
e o valor ofuscado com HMAC sha256


# Configurações
HOST = '192.168.100.130'
PORT = 4443
HOTP_COUNTER = 0  # Inicializa o contador

VAULT_URL = 'http://192.168.100.130:8200'
VAULT_TOKEN = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

# Função para gerar a semente a partir do arquivo poetry.txt
def generate_seed(poetry_lines):
    seed = ''
    seed += ''.join(poetry_lines[3][:16])  # 16 primeiros caracteres da linha 4
    seed += poetry_lines[0][57] if len(poetry_lines[0]) > 57 else 'X'  # Caractere na posição 58
    
    # Gera um OTP "dummy" para pegar o valor do OTP e garantir que seja base32
    dummy_secret = base64.b32encode(b'secret').decode('utf-8')  # Usar um segredo dummy em base32
    totp = pyotp.TOTP(dummy_secret)
    otp = totp.now()
    
    # Quantidade de linhas no arquivo
    num_lines = len(poetry_lines)
    
    # Se os últimos 2 dígitos do OTP forem maiores que o número de linhas, use o penúltimo dígito
    if int(otp[-2:]) > num_lines:
        seed += otp[-2]
    else:
        seed += otp[-2:]

    # Converta a semente para base32
    seed = base64.b32encode(seed.encode()).decode('utf-8')

    return seed

def generate_hotp(counter, seed):
    hotp = pyotp.HOTP(seed)
    return hotp.at(counter)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

# class MockVaultClient:
#     def read(self, path):
#         return {
#             'data': {
#                 'username': 'mock_username',
#                 'password': 'mock_password_123'
#             }
#         }

def get_credential_from_vault():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    try:
        secret = client.read('database-glpi/creds/access-db')
        return f"{secret['data']['username']}:{secret['data']['password']}"
    except Exception as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def obfuscate_credential(credential, seed):
    obfuscated = ''.join(chr(ord(c) ^ ord(seed[i % len(seed)])) for i, c in enumerate(credential))
    return base64.b64encode(obfuscated.encode()).decode()

def validate_hotp(client_otp_hash, seed, look_ahead=10):
    global HOTP_COUNTER
    for i in range(look_ahead):
        server_otp = generate_hotp(HOTP_COUNTER + i, seed)
        server_otp_hash = hash_otp(server_otp)
        if hmac.compare_digest(client_otp_hash, server_otp_hash):
            HOTP_COUNTER = HOTP_COUNTER + i + 1  # Incrementa o contador após sucesso
            return True
    return False

def main():
    global HOTP_COUNTER
    poetry_lines = read_poetry_file()

    seed = generate_seed(poetry_lines)  # Gera a semente aqui

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
                    
                    # Verificar se o HOTP do cliente é válido
                    if validate_hotp(client_otp_hash, seed):
                        secure_conn.send(b"OTP Valido")
                    else:
                        secure_conn.send(b"OTP Invalido")
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
                    
                    # Ofuscar credencial
                    obfuscated_cred = obfuscate_credential(credential, seed)
                    
                    # Enviar credencial ofuscada
                    secure_conn.send(f"{obfuscated_cred}|{hash_otp(credential)}".encode())
                    
                    print("Credencial enviada com sucesso.")
                
                except Exception as e:
                    print(f"Erro durante a comunicação: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()
