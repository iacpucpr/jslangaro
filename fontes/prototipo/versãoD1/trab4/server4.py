import socket
import ssl
import pyotp
import hmac
import hvac
import hashlib
import base64

HOST = '192.168.100.130'
PORT = 4443

a) Validação do contador no servidor
Caso esteja fora de sincronia, precisa de ação do operador

b) Geração da credential.txt para validar como fica a credencial ofuscada no arquivo
    Se puder deixar como estava antes, imprimindo a credential trazida do metodo, 
    acessando o vault
    E a ofuscação depois de feita, como fica a diferença entre eles

VAULT_URL = 'http://192.168.100.130:8200'
VAULT_TOKEN = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

def generate_seed(poetry_lines):
    seed = ''
    seed += ''.join(poetry_lines[3][:16])  # 16 primeiros caracteres da linha 4
    seed += poetry_lines[0][57] if len(poetry_lines[0]) > 57 else 'X'  # Caractere na posição 58
    
    # Gera TOTP baseado no segredo "secret"
    totp = pyotp.TOTP(base64.b32encode('secret'.encode()).decode())
    otp = totp.now()
    
    # Quantidade de linhas no arquivo
    num_lines = len(poetry_lines)
    
    # Se os últimos 2 dígitos do OTP forem maiores que o número de linhas, use o penúltimo dígito
    if int(otp[-2:]) > num_lines:
        seed += otp[-2]
    else:
        seed += otp[-2:]

    return seed

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return context

def obfuscate_credential(credential, seed, counter):
    # Ofusca a credencial com seed + credencial + contador usando HMAC SHA256
    key = f"{seed}{credential}{counter}"
    return hmac.new(key.encode(), credential.encode(), hashlib.sha256).hexdigest()

def load_state(filename='server_state.txt'):
    try:
        with open(filename, 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0

def save_state(counter, filename='server_state.txt'):
    with open(filename, 'w') as f:
        f.write(str(counter))

def get_credential_from_vault():
    # Função que pega a credencial (não alterada)
    # return "usuario_mock:senha_mock_123"
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        print("Não foi possível autenticar no Vault")
        return None
    try:
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['username'], secret['data']['password']
    except hvac.exceptions.VaultError as e:
        print(f"Erro ao acessar o Vault: {e}")
        return None

def main():
    poetry_lines = read_poetry_file()
    seed = generate_seed(poetry_lines)
    counter = load_state()
    
    context = create_ssl_context()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        
        print(f"Server started on {HOST}:{PORT}")
        
        while True:
            conn, addr = sock.accept()
            with context.wrap_socket(conn, server_side=True) as secure_conn:
                print(f"Secure connection established with {addr}")
                
                try:
                    # Recebe o hash do OTP do cliente
                    client_otp_hash = secure_conn.recv(1024).decode()
                    print(f"Received OTP hash from client: {client_otp_hash}")
                    
                    # Gera o OTP do servidor e compara
                    totp = pyotp.TOTP(base64.b32encode(seed.encode()).decode())
                    server_otp = totp.now()
                    server_otp_hash = hash_otp(server_otp)
                    
                    if hmac.compare_digest(client_otp_hash, server_otp_hash):
                        secure_conn.send(b"OTP Valid")
                        print("OTP validated successfully")
                    else:
                        secure_conn.send(b"OTP Invalid")
                        print("OTP validation failed")
                        continue
                    
                    # Recebe a solicitação do cliente
                    request = secure_conn.recv(1024).decode()
                    if request != "Request Credential":
                        continue
                    
                    # Obtém e ofusca a credencial
                    credential = get_credential_from_vault()
                    obfuscated_cred = obfuscate_credential(credential, seed, counter)
                    
                    # Envia a credencial ofuscada
                    secure_conn.send(obfuscated_cred.encode())
                    print("Credential sent successfully.")
                    
                    # Atualiza o contador
                    counter += 1
                    save_state(counter)
                    
                except Exception as e:
                    print(f"Error during communication: {e}")
                
                finally:
                    secure_conn.close()

if __name__ == "__main__":
    main()
