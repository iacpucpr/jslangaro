import socket
import ssl
import pyotp
import base64
import hmac
import hvac
import hashlib
from datetime import datetime  # Importa a biblioteca datetime

def xor_encrypt_decrypt(dados, key):
    # Função pata ofuscação utilizando XOR
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(dados, key))

def log_message(message , separator=False):
    # Função para registrar mensagens no arquivo de log com data e hora
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Obtém data e hora atual
    with open('server_log.txt', 'a') as log_file:
        if separator:
            # Adiciona separador seguido de um espaço
            log_file.write("_____________________________________________________________________________________________\n")  
            log_file.write("\n")
        else:
            log_file.write(f"[{current_time}] {message}\n")  # Adiciona data/hora à mensagem de log

def read_env_file(filename):
    # Função para ler o arquivo de dados.txt (contém a semente do OTP + Token do Vault
    env_vars = {}
    with open(filename, 'r') as file:
        for line in file:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                env_vars[key] = value.strip("'")
    return env_vars

def inicializa_OTP():
    # Lê as variáveis de ambiente do arquivo dados.txt
    env_vars = read_env_file('dados.txt')

    # Obtém a chave secreta e configura o OTP
    OTP_SECRET  = env_vars.get('OTP_SECRET')  # Segredo é lido como base32
    totp = pyotp.TOTP(OTP_SECRET)             # Configura o TOTP com o segredo OTP
    
    if not OTP_SECRET:
        print("Erro: OTP_SECRET não está definido no arquivo dados.txt")
        return None

    try:
        # Configura o TOTP com o segredo OTP
        totp = pyotp.TOTP(OTP_SECRET)
        return totp
    except Exception as e:
        print(f"Erro ao inicializar o TOTP: {e}")
        return None    

def get_credential_from_vault():
    # Função para obtenção de credenciais do Vault
    
    # Lê as variáveis de ambiente do Vault
    env_vars = read_env_file('dados.txt')
    VAULT_URL = env_vars.get('VAULT_URL')
    VAULT_TOKEN = env_vars.get('VAULT_TOKEN')

    if not VAULT_URL or not VAULT_TOKEN:
        print("Erro: VAULT_URL ou VAULT_TOKEN não definidos.")
        return

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
    
def run_server():
    host = '192.168.100.130'  # Endereço IP para escuta
    port = 5000               # Porta para escuta
    
    # Inicializa o TOTP
    totp = inicializa_OTP()  # Chama a função para inicializar o OTP

    if totp is None:
        print("Erro: não foi possível inicializar o TOTP.")
        return

    # Cria e configura o socket do servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    # Cria o contexto SSL e o aplica ao socket
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # Carrega o certificado e a chave privada
    ssl_server_socket = context.wrap_socket(server_socket, server_side=True)  # Envolve o socket com SSL

    log_message("Aguardando conexão do cliente...")
    print("Aguardando conexão do cliente...")
    
    # Aceita a conexão de um cliente
    client_socket, client_address = ssl_server_socket.accept()
    log_message(f"Conexão estabelecida com {client_address}")
    print(f"Conexão estabelecida com {client_address}")

    # Gera o OTP atual e envia ao cliente
    otp_tot = totp.now()  # Gera o OTP atual
    otp     = base64.b64encode(otp_tot.encode()).decode()
    client_socket.sendall(otp.encode('utf-8'))  # Envia o OTP para o cliente
    log_message(f"OTP gerado e enviado para o cliente: {otp}")
    print(f"OTP gerado e enviado para o cliente: {otp}")
    print(f"OTP TOP: {otp_tot}")

    # Ofusca credencial para envio seguro ao cliente
    credential = get_credential_from_vault()
    if credential is None:
        print("Erro ao obter credenciais do Vault.")
        return
    ofuscacao_credential = ':'.join(credential)
    #key = hashlib.pbkdf2_hmac('sha256', otp.encode(), b'salt', 100000)
    #obfuscated_cred = base64.b64encode(''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(concatenated_credential)).encode()).decode()  # Ofuscar credencial
    #encrypted_credential = xor_encrypt_decrypt(ofuscacao_credential, otp_ofuscada)
    #obfuscated_cred = hashlib.sha256(encrypted_credential.encode()).hexdigest()
    #obfuscated_cred = xor_encrypt_decrypt(ofuscacao_credential, otp)
    #hash_obfuscated_cred = hashlib.sha256(encrypted_credential.encode()).hexdigest()
    obfuscated_cred = xor_encrypt_decrypt(ofuscacao_credential, otp)
    hash_obfuscated_cred = hashlib.sha256(obfuscated_cred.encode()).hexdigest()
    
    # Ofusca credencial usando XOR e envia ao cliente
    client_socket.sendall(obfuscated_cred.encode('utf-8'))  # Envia a credencial ofuscada
    log_message(f"Credencial ofuscada enviada para o cliente: {obfuscated_cred.strip()}")  # a função strip() Garante que a credencial esteja na mesma linha
    print(f"Credencial ofuscada enviada para o cliente: {obfuscated_cred.strip()}")
    
    # Hash da credencial ofuscada e envia ao cliente
    client_socket.sendall(hash_obfuscated_cred.encode('utf-8'))  # Envia a hash da credencial ofuscada
    log_message(f"Hash da credenciais ofuscada e envia ao cliente: {hash_obfuscated_cred.strip()}")  # a função strip() Garante que a credencial esteja na mesma linha
    print(f"hash da credenciais ofuscada e envia ao cliente: {hash_obfuscated_cred.strip()}")
    
    # Recebe o OTP do cliente e valida com o OTP gerado
    client_otp = client_socket.recv(1024).decode('utf-8')  # Recebe o OTP do cliente
    server_otp_hash = otp
    if hmac.compare_digest(client_otp, server_otp_hash):
        client_socket.sendall("Autenticação bem-sucedida!".encode('utf-8'))
        log_message("Autenticação bem-sucedida!")
        print("Autenticação bem-sucedida!")
    else:
        client_socket.sendall("Falha na autenticação.".encode('utf-8'))
        log_message("Falha na autenticação.")
        print("Falha na autenticação.")
    
    # Recebe dados do cliente e responde
    data = client_socket.recv(1024).decode('utf-8')  # Recebe dados do cliente
    client_socket.sendall("Mensagem recebida com sucesso.".encode('utf-8'))  # Responde ao cliente
    log_message(f"Dados recebidos do cliente: {data}")
    print(f"Dados recebidos do cliente: {data}")

    # Fecha as conexões
    client_socket.close()
    ssl_server_socket.close()
    log_message("Servidor encerrado.")
    print("Servidor encerrado.")
    
    # Adiciona uma linha de separação ao final de cada interação
    log_message("", separator=True)

if __name__ == "__main__":
    run_server()
