import socket
import ssl
import pyotp
import hmac
import hashlib
import base64
import os

# Configurações
SERVER_HOST = '192.168.100.130'
SERVER_PORT = 4443
MAX_ATTEMPTS = 5  # Número máximo de tentativas para validar o OTP
HOTP_COUNTER = 0  # Inicializa o contador

def read_poetry_file(filename='poetry.txt'):
    with open(filename, 'r', encoding='utf-8') as file:
        return file.readlines()

# Função para gerar a semente a partir do arquivo poetry.txt
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

    # Converte a semente para base32
    return base64.b32encode(seed.encode()).decode()

def generate_hotp(counter, seed):
    hotp = pyotp.HOTP(seed)
    return hotp.at(counter)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="server.crt")
    context.check_hostname = False
    return context

def obfuscate_credential(credential, seed):
    obfuscated = ''.join(chr(ord(c) ^ ord(seed[i % len(seed)])) for i, c in enumerate(credential))
    return base64.b64encode(obfuscated.encode()).decode()

def deobfuscate_credential(obfuscated_cred, seed):
    decoded = base64.b64decode(obfuscated_cred.encode()).decode()
    deobfuscated = ''.join(chr(ord(c) ^ ord(seed[i % len(seed)])) for i, c in enumerate(decoded))
    return deobfuscated

def update_hotp_counter(new_value):
    global HOTP_COUNTER
    HOTP_COUNTER = new_value

def main():
    global HOTP_COUNTER
    poetry_lines = read_poetry_file()
    seed = generate_seed(poetry_lines)  # Gera a semente aqui

    context = create_ssl_context()
    
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
            try:
                for i in range(MAX_ATTEMPTS):  # Tenta até 5 vezes
                    current_counter = HOTP_COUNTER + i
                    otp = generate_hotp(current_counter, seed)
                    otp_hash = hash_otp(otp)

                    print(f"Tentativa {i+1}: Enviando OTP hash para o contador: {current_counter}")
                    secure_sock.send(otp_hash.encode())

                    response = secure_sock.recv(1024).decode()
                    print(f"Resposta do servidor: {response}")

                    if response == "OTP Valido":
                        print("OTP validado com sucesso!")
                        update_hotp_counter(current_counter + 1)  # Atualiza o contador
                        break  # Sai do loop de tentativas
                    else:
                        print(f"Falha na validação do OTP: {response}")

                else:  # Este bloco é executado se o loop não for interrompido (ou seja, todas as tentativas falharam)
                    print("Todas as tentativas falharam. Encerrando.")
                    return
                
                # Solicitar credencial
                secure_sock.send(b"Solicitar Credencial")
                response = secure_sock.recv(4096).decode()
                
                if response == "Erro ao obter credencial":
                    print("O servidor não pôde fornecer a credencial")
                    return

                data = response.split('|')
                if len(data) != 2:
                    print("Formato de resposta inválido")
                    return

                obfuscated_cred, _ = data
                deobfuscated_cred = deobfuscate_credential(obfuscated_cred, seed)
                print("Credencial ofuscada:", obfuscated_cred)
                print("Credencial desofuscada:", deobfuscated_cred)

                with open('credential.txt', 'w') as f:
                    f.write(f"Ofuscada: {obfuscated_cred}\n")
                    f.write(f"Desofuscada: {deobfuscated_cred}")

                print("Credenciais salvas com sucesso em 'credential.txt'.")
            
            except Exception as e:
                print(f"Erro durante a comunicação: {e}")
            finally:
                secure_sock.close()

if __name__ == "__main__":
    print(f"HOTP_COUNTER inicial: {HOTP_COUNTER}")
    main()
