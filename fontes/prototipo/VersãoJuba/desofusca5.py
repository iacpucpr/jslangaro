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

# 4. Gerar MAC
def generate_mac(data, key):
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

# 5. Verificar o MAC
def verify_mac(data, key, mac):
    calculated_mac = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_mac, mac)

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

# Etapa 1: Desofuscar a credencial
retrieved_password = deobfuscate_credential(file_path, key)

# Etapa 2: Gerar OTP
otp = apply_otp(totp_key)
print(f"OTP gerado: {otp}")

# Etapa 3: Gerar MAC
data = retrieved_password + otp
mac = generate_mac(data, key)
print(f"MAC gerado: {mac}")

# Etapa 4: Verificar o MAC
mac_valid = verify_mac(data, key, mac)
print(f"MAC válido: {mac_valid}")

# Etapa 5: Se o MAC for válido, salvar a credencial original em um novo arquivo
if mac_valid:
    save_original_credential(retrieved_password, output_file_path)
    print(f"Credencial original salva em: {output_file_path}")
else:
    print("Falha na verificação do MAC. Credencial não foi salva.")

