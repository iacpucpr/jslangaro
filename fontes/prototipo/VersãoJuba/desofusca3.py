import hvac
import base64
import pyotp
import hmac
import hashlib

# 1. Função para desofuscar a credencial
def deobfuscate_credential(file_path, key):
    with open(file_path, 'r') as f:
        obfuscated_base64 = f.read()
    
    obfuscated = base64.b64decode(obfuscated_base64).decode('utf-8')
    password = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(obfuscated))
    
    return password

# 2. Função para verificar a OTP
def verify_otp(otp, totp_key):
  # baseado em chave fixa
    #totp = pyotp.TOTP(totp_key)
    #return totp.verify(otp)
    # Supondo que o TOTP seja gerado com uma chave baseada no usuário
    totp = pyotp.TOTP(totp_key)
    return totp.verify(otp)

# 3. Função para verificar o MAC
def verify_mac(data, key, mac):
    calculated_mac = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_mac, mac)

# 4. Função para verificar se a credencial é válida no Vault
def validate_credentials_in_vault(vault_address, token, secret_path, username, password):
    client = hvac.Client(url='http://192.168.100.130:8200', token='hvs.jloguG2rfDlxmkAIHoQH7P6g')
    
    if not client.is_authenticated():
        raise Exception("Falha na autenticação ao Vault")
    
    secret = client.read('database-glpi/creds/access-db')
    
    return secret['data']['username'] == username and secret['data']['password'] == password

# Exemplo de uso
vault_address = 'http://192.168.100.130:8200'  # Endereço do Vault
vault_token = 'hvs.jloguG2rfDlxmkAIHoQH7P6g'  # Token de acesso ao Vault
secret_path = 'database-glpi/creds/access-db'  # Caminho do segredo no Vault
file_path = 'credential.txt'  # Caminho do arquivo com a credencial ofuscada
key = 'IACPUCPR2024'  # Chave de ofuscação e MAC
user = 'vault'  # Nome de usuário
#otp_input = '148485'  # OTP recebido do usuário
#mac_input = 'c431b32f3df51deed8bb58f8cc26dc977d195f1c6a2055e9e92d4aa653a7f401'  # MAC recebido para verificação
totp_key = 'JBSWY3DPEHPK3PXP'  # Chave TOTP fixa (deve ser segura e secreta)

# Desofuscar a credencial
password = deobfuscate_credential(file_path, key)

# Verificar a OTP
#otp_valid = verify_otp(otp_input, user)
otp_valid = verify_otp(otp, totp_key)
print(f"OTP válido: {otp_valid}")

# Verificar o MAC
data = password + otp
mac_valid = verify_mac(data, key, mac)
print(f"MAC válido: {mac_valid}")

# Validar credenciais no Vault
if otp_valid and mac_valid:
    credentials_valid = validate_credentials_in_vault(vault_address, vault_token, secret_path, user, password)
    print(f"Credenciais válidas no Vault: {credentials_valid}")
else:
    print("Falha na verificação de OTP ou MAC")
