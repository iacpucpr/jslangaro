import socket
import ssl
import pyotp
import base64
import hashlib

def xor_encrypt_decrypt(data, key):
    # Função de criptografia/descriptografia XOR
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key))

def run_client():
    host = '127.0.0.1'  # Endereço IP do servidor
    port = 8080         # Porta para conexão

    # Segredo OTP usado para gerar e verificar OTPs
    OTP_SECRET = 'UOVSHEO5LROFRXDPPPWDPMOEYKLSKVNZ'  # Segredo em base32 
    totp = pyotp.TOTP(OTP_SECRET)  # Configura o TOTP com o segredo OTP

    # Cria e configura o socket do cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Cria um contexto SSL para o cliente
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False       # Para certificados autoassinados, desabilite a verificação de hostname
    context.verify_mode = ssl.CERT_NONE  # Para certificados autoassinados, desabilite a verificação do certificado

    # Envolve o socket com SSL
    ssl_client_socket = context.wrap_socket(client_socket, server_hostname=host)
    
    # Log de depuração para tentativa de conexão
    print(f"Tentando conectar ao servidor em {host}:{port}...")

    try:
        # Estabelece a conexão SSL com o servidor
        ssl_client_socket.connect((host, port))
        print("Conexão estabelecida com sucesso!")

        # Recebe o OTP do servidor
        otp_from_server = ssl_client_socket.recv(1024).decode('utf-8')
        print(f"OTP recebido do servidor: {otp_from_server}")

        # Recebe a credencial ofuscada do servidor
        obfuscated_cred = ssl_client_socket.recv(1024).decode('utf-8')                              
        print(f"Credencial ofuscada recebida do servidor: {obfuscated_cred}")
        
        # Recebe o hasch da credencial ofuscada do servidor
        hash_obfuscated_cred = ssl_client_socket.recv(1024).decode()                              
        print(f"Hasch da credencial ofuscada recebida do servidor: {hash_obfuscated_cred}")
        
        # Valida o hash da credencial ofuscada
        local_hash = hashlib.sha256(obfuscated_cred.encode()).hexdigest()
        if local_hash != hash_obfuscated_cred:
            print("Erro: o hash da credencial ofuscada não coincide. A mensagem pode ter sido alterada.")
            ssl_client_socket.close()
            return 
        else:
            print("Hash da credencial ofuscada validado com sucesso!")

        # Desofusca a credencial usando o OTP recebido
        decrypted_credential = xor_encrypt_decrypt(obfuscated_cred, otp_from_server)
        print(f"Credencial desofuscada: {decrypted_credential}")

        # Gera o OTP no lado do cliente e envia de volta ao servidor
        otp_tot_cliente = totp.now()  # Gera o OTP atual
        client_otp = base64.b64encode(otp_tot_cliente.encode()).decode()
        
        print(f"OTP gerado pelo cliente: {client_otp}")
        ssl_client_socket.sendall(client_otp.encode('utf-8'))

        # Recebe a resposta de autenticação do servidor
        auth_response = ssl_client_socket.recv(1024).decode('utf-8')
        print(f"Resposta de autenticação do servidor: {auth_response}")

        # Verifica a resposta de autenticação
        if "bem-sucedida" in auth_response:
            # Envia uma mensagem ao servidor após a autenticação
            ssl_client_socket.sendall("Credencial gerada e armazenada no servidor!".encode('utf-8'))

            # Recebe a resposta do servidor
            data = ssl_client_socket.recv(1024).decode('utf-8')
            print(f"Dados recebidos do servidor: {data}")
        else:
            print("Autenticação falhou.")

    except ConnectionRefusedError:
        print(f"Conexão recusada ao tentar conectar a {host}:{port}. Verifique se o servidor está em execução e acessível.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

    finally:
        # Fecha a conexão
        ssl_client_socket.close()
        print("Conexão fechada.")

if __name__ == "__main__":
    run_client()
