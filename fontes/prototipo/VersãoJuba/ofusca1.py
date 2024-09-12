import hvac
import base64
import pyotp
import hmac
import hashlib
import os

# 1. Obter credenciais do Vault
def get_credentials_from_vault(vault_address, token, secret_path):
    client = hvac.Client(url='http://192.168.100.130:8200', token='hvs.jloguG2rfDlxmkAIHoQH7P6g')
    secret = client.read('database-glpi/creds/access-db')
    return secret['data']['username'], secret['data']['password']

# 2. Ofuscar e armazenar a credencial
def obfuscate_and_store_credential(password, file_path, key):
    # Ofuscação simples usando XOR
    obfuscated = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(password))
    # Codificar em base64 para armazenamento
    obfuscated_base64 = base64.b64encode(obfuscated.encode('utf-8')).decode('utf-8')
    
    with open(file_path, 'w') as f:
        f.write(obfuscated_base64)

# 3. Desofuscar e aplicar OTP
def deobfuscate_and_apply_otp(file_path, key, user):
    with open(file_path, 'r') as f:
        obfuscated_base64 = f.read()
    
    obfuscated = base64.b64decode(obfuscated_base64).decode('utf-8')
    # Desofuscar usando XOR
    password = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(obfuscated))
    
    # Gerar OTP baseado no usuário
    #totp = pyotp.TOTP(pyotp.random_base32())
    #otp = totp.now()
    
    #return password, otp

    # Gerar OTP baseado em uma chave TOTP fixa
    totp = pyotp.TOTP(totp_key, interval=60)
    otp = totp.now()

    return password, otp

# 4. Gerar MAC
def generate_mac(data, key):
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

# Exemplo de uso
vault_address = 'http://192.168.100.130:8200'  # Endereço do Vault
vault_token = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'  # Token de acesso ao Vault
secret_path = 'database-glpi/creds/access-db'  # Caminho do segredo no Vault
user = 'vault'  # Nome de usuário
file_path = 'credential.txt'  # Caminho para armazenar a credencial ofuscada
key = 'IACPUCPR2024'  # Chave de ofuscação e MAC
totp_key = 'JBSWY3DPEHPK3PXP'  # Chave TOTP fixa (deve ser segura e secreta)

# Obter credenciais do Vault
username, password = get_credentials_from_vault(vault_address, vault_token, secret_path)

# Ofuscar e armazenar a credencial
obfuscate_and_store_credential(password, file_path, key)

# Desofuscar e aplicar OTP
retrieved_password, otp = deobfuscate_and_apply_otp(file_path, key, user)

# Gerar MAC
mac = generate_mac(retrieved_password + otp, key)

print(f"Retrieved Password: {retrieved_password}")
print(f"OTP: {otp}")
print(f"MAC: {mac}")
