import hvac
import base64
import pyotp
import hmac
import hashlib

# 1. Função para obter credenciais do Vault
#def get_credentials_from_vault(vault_address, token, secret_path):
#    client = hvac.Client(url=vault_address, token=token)
#    secret = client.read(secret_path)
#    return secret['data']['username'], secret['data']['password']

# 2. Desofuscar a credencial
def deobfuscate_credential(file_path, key):
    with open(file_path, 'r') as f:
        obfuscated_base64 = f.read()
    
    obfuscated = base64.b64decode(obfuscated_base64).decode('utf-8')
    password = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(obfuscated))
    
    return password

# 3. Aplicar OTP
def apply_otp(totp_key):
    totp = pyotp.TOTP(totp_key)
    otp = totp.now()
    return otp

# 4. Verificar a OTP
def verify_otp(otp, totp_key):
    totp = pyotp.TOTP(totp_key)
    return totp.verify(otp)

# 5. Gerar MAC
def generate_mac(data, key):
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

# 6. Salvar a credencial original em um novo arquivo
def save_original_credential(password, file_path):
    with open(file_path, 'w') as f:
        f.write(password)

# Exemplo de uso
vault_address = 'http://192.168.100.130:8200'  # Endereço do Vault
vault_token = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'  # Token de acesso ao Vault
secret_path = 'database-glpi/creds/access-db'  # Caminho do segredo no Vault
file_path = 'credential.txt'  # Caminho do arquivo com a credencial ofuscada
output_file_path = 'credential2.txt'  # Caminho do arquivo para salvar a credencial original
key = 'IACPUCPR2024'  # Chave de ofuscação e MAC
totp_key = 'JBSWY3DPEHPK3PXP'  # Chave TOTP fixa

# Etapa 1: Obter a credencial original do Vault
#username, password = get_credentials_from_vault(vault_address, vault_token, secret_path)

# Etapa 2: Desofuscar a credencial
retrieved_password = deobfuscate_credential(file_path, key)

# Etapa 3: Salvar a credencial original em um novo arquivo
save_original_credential(retrieved_password, output_file_path)

print(f"Credencial original salva em: {output_file_path}")

