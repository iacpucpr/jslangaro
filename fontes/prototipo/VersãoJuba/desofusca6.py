import hvac
import base64
import pyotp
import hmac
import hashlib

# 1. Verificar MAC
def verify_mac(data, key, mac):
    calculated_mac = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_mac, mac)

# 2. Desofuscar a credencial e verificar OTP
def deobfuscate_and_verify_otp(file_path, key, totp_key, mac_to_verify):
    with open(file_path, 'r') as f:
        obfuscated_base64 = f.read()

    obfuscated = base64.b64decode(obfuscated_base64).decode('utf-8')
    password = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(obfuscated))

    # Gerar OTP baseado em uma chave TOTP fixa
    totp = pyotp.TOTP(totp_key, interval=60)
    otp = totp.now()

    # Verificar MAC
    data = password + otp
    mac_valid = verify_mac(data, key, mac_to_verify)

    return password if mac_valid else None, mac_valid

# 3. Salvar a credencial desofuscada em credential3.txt
def save_deobfuscated_credential(password, file_path):
    with open(file_path, 'w') as f:
        f.write(password)

# Exemplo de uso
file_path = 'credential.txt'  # Caminho do arquivo que contém a credencial ofuscada
output_file_path = 'credential3.txt'  # Caminho do arquivo para salvar a credencial desofuscada
key = 'IACPUCPR2024'  # Chave de ofuscação e MAC
totp_key = 'JBSWY3DPEHPK3PXP'  # Chave TOTP fixa
mac_to_verify = '6e6d227bdbafcb129c6ad7872c77e26d4f75fb515a7dccc547e8a5258fbf3a4a'  # Substitua pelo MAC real calculado no processo original

# Desofuscar e verificar o MAC e OTP
retrieved_password, mac_valid = deobfuscate_and_verify_otp(file_path, key, totp_key, mac_to_verify)

if mac_valid and retrieved_password:
    save_deobfuscated_credential(retrieved_password, output_file_path)
    print(f"Credencial desofuscada e salva em: {output_file_path}")
else:
    print("Falha na verificação do MAC. Credencial não foi salva.")

