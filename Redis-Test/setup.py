import pyotp
import base64
import hmac
import hashlib
import redis
import hvac
import os
from dotenv import load_dotenv

# Configuração do Vault e Redis
load_dotenv()

VAULT_URL = os.getenv('VAULT_URL')
VAULT_TOKEN = os.getenv('VAULT_TOKEN')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

r = redis.Redis(host='localhost', port=6379, password=REDIS_PASSWORD, db=0)

# Funções para ler poesia e gerar seed
def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

def generate_seed(poetry_lines, otp):
    seed = poetry_lines[3][:8] + poetry_lines[0][-1] + poetry_lines[1][len(poetry_lines[1]) // 2] + poetry_lines[-1][:2]
    seed += otp[-4:] + otp[-2:]
    return seed

# Função para obter a credencial do Vault
def get_credential_from_vault():
    client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
    if not client.is_authenticated():
        print("Falha na autenticação com o Vault")
        return None
    try:
        secret = client.read('database-glpi/creds/access-db')
        return secret['data']['username'], secret['data']['password']
    except hvac.exceptions.VaultError as e:
        print(f"Erro no Vault: {e}")
        return None

# Configuração do TOTP e HOTP para ofuscação
user_id = "db0010"
poetry_lines = read_poetry_file()
totp = pyotp.TOTP(base64.b32encode(generate_seed(poetry_lines, user_id).encode()).decode())
otp_user_id = totp.now()

# Geração do HOTP para ofuscação da credencial
seed = "poetry_lines_seed"  # Seed fixa para HOTP (somente para ofuscação)
counter = 0
otp = pyotp.HOTP(base64.b32encode(seed.encode()).decode())
hotp_user_id = otp.at(counter)

# Obtenção e ofuscação da credencial
vault_credential = get_credential_from_vault()
if not vault_credential:
    exit("Erro ao obter credencial do Vault")

# Combina username e password com HOTP
credential_combined = vault_credential[0] + vault_credential[1] + hotp_user_id
def obfuscate_credential(credential, hotp):
    ofuscated_bytes = bytearray()
    for i in range(len(credential)):
        ofuscated_bytes.append(ord(credential[i]) ^ ord(hotp[i % len(hotp)]))
    return base64.b64encode(ofuscated_bytes).decode('utf-8')

obfuscated_credential = obfuscate_credential(credential_combined, hotp_user_id)

# Geração de HMAC usando TOTP para autenticação entre camadas
def generate_hmac(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

hmac_signature = generate_hmac(otp_user_id, user_id)

# Armazena no Redis
r.set("user_id", user_id)
r.set("otp_user_id", otp_user_id)
r.set("vault_username", vault_credential[0])
r.set("vault_password", vault_credential[1])
r.set("obfuscated_credential", obfuscated_credential)
r.set("hmac_signature", hmac_signature)
print("Setup completo.")
