from flask import Flask, request, jsonify, render_template_string
import hmac
import hashlib
import pyotp
import hvac
import requests
import base64
import logging
import ssl
import urllib3
from threading import Thread
import time  
from datetime import datetime

# Variáveis globais para armazenar credenciais e tempo de validade
stored_credentials = None
vault_last_fetched = None

# Duração de validade das credenciais em segundos (8 horas)
CREDENTIALS_VALIDITY_PERIOD = 8 * 3600

# Suprime avisos de certificados não verificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configuração do logging
#logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.basicConfig(level=logging.CRITICAL)  # Desativa logs INFO e WARNING na console

# Lista de logs recentes
recent_logs = []

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"{timestamp} - {message}"
    recent_logs.append(message)
    if len(recent_logs) > 30:  # Limita os logs a 20 entradas
        recent_logs.pop(0)
    logging.info(message)
#    log_message(message)  # Registrar apenas na página

def generate_shared_secret(file_path):
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            file_content = f.read()
        if len(lines) < 4:
            raise ValueError("verifique")

        poetry_line_4 = lines[3].strip()[:16]
        if len(poetry_line_4) < 16:
            raise ValueError("Linha 4 deve ter pelo menos 16 caracteres no arquivo poetry.txt.")

        poetry_line_1_char_58 = lines[0].strip()[57] if len(lines[0].strip()) >= 58 else "X"
        file_hash = hashlib.sha256(file_content.encode()).hexdigest()[:16]
        seed = poetry_line_4 + poetry_line_1_char_58 + file_hash
        seed_b32 = base64.b32encode(seed.encode()).decode()

        log_message(f"Generated seed: {seed_b32}")
        return seed_b32

    except FileNotFoundError:
        raise FileNotFoundError(f"Arquivo {file_path} não encontrado.")
    except Exception as e:
        raise RuntimeError(f"Erro ao gerar a semente: {e}")

shared_secret = generate_shared_secret("/home/iacpucpr/safecredential/poetry.txt")
vault_client = hvac.Client(url="http://192.168.100.130:8200", token="VAR_ENT")

counter = 146578

@app.route('/access-mariadb', methods=['POST'])
def access_mariadb():
    global counter, stored_credentials, vault_last_fetched

    # Verificar se as credenciais do Vault estão em memória e ainda válidas
    if stored_credentials and time.time() - vault_last_fetched < CREDENTIALS_VALIDITY_PERIOD:
        db_username = stored_credentials['username']
        db_password = stored_credentials['password']
        otp_hotp = stored_credentials['hotp']
        log_message(f"Usando credenciais armazenadas em memória: username={db_username}, HOTP={otp_hotp}")
    else:
        # Buscar credenciais do Vault
        secret_path = "database-glpi/creds/access-db"
        try:
            response = vault_client.read(secret_path)
            db_username = response['data']['username']
            db_password = response['data']['password']
            hotp = pyotp.HOTP(shared_secret)
            otp_hotp = hotp.at(counter)
            stored_credentials = {'username': db_username, 'password': db_password, 'hotp': otp_hotp}
            vault_last_fetched = time.time()
            log_message(f"Credenciais obtidas do Vault: username={db_username}, HOTP={otp_hotp}")
        except Exception as e:
            log_message(f"Erro ao acessar o Vault: {e}")
            return jsonify({"status": "error", "message": "Erro ao acessar o Vault."}), 500

    # Geração do TOTP para validação
    totp = pyotp.TOTP(shared_secret)
    otp_totp = totp.now()
    log_message(f"TOTP Gerado: {otp_totp}")

    def xor_encrypt(data, key):
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key))

    otp_str = str(otp_hotp).zfill(len(db_password))
    credential_obfuscated = xor_encrypt(db_password, otp_str)
    log_message(f"Credential Ofuscada: {credential_obfuscated}")

    # Geração do HMAC usando username e TOTP
    message = f"{db_username}:{otp_totp}".encode()
    hmac_signature = hmac.new(shared_secret.encode(), message, hashlib.sha256).hexdigest()
    log_message(f"HMAC Gerado: {hmac_signature}")

    mariadb_validator_url = "https://127.0.0.1:5001/validate"
    payload = {
        "username": db_username,
        "credential_obfuscated": credential_obfuscated,
        "otp": otp_totp,
        "hmac": hmac_signature
    }

    try:
        log_message("Enviando payload para MariaDB Validator...")
        log_message(f"Payload: {payload}")
        validator_response = requests.post(mariadb_validator_url, json=payload, verify=False)
        response_json = validator_response.json()

        if validator_response.status_code == 200 and response_json.get("valid"):
            log_message("Validação bem-sucedida.")
            counter += 1  # Incrementa o contador apenas em caso de sucesso
            return jsonify({"status": "Access Granted"}), 200
        else:
            error = response_json.get("error", "Erro desconhecido.")
            log_message(f"Falha na validação: {error}")
            return jsonify({"status": "Access Denied", "error": error}), 403
    except requests.exceptions.RequestException as e:
        log_message(f"Erro ao conectar ao MariaDB Validator: {e}")
        return jsonify({"status": "error", "message": "Erro ao conectar ao MariaDB Validator."}), 500


@app.route('/logs', methods=['GET'])
def logs():
    """
    Exibe logs recentes.
    """
    return jsonify({"logs": recent_logs})

@app.route('/admin', methods=['GET'])
def admin():
    """
    Página de administração com status e logs.
    """
    log_message(f"Logs sendo enviados para a página admin: {recent_logs}")
    html = """
    <html>
    <head><title>Admin - SafeCredential/MariaDBValidator</title></head>
    <body>
        <h1>Administração</h1>
        <h2>Logs Recentes</h2>
        <ul>
            {% for log in logs %}
                <li>{{ log }}</li>
            {% endfor %}
        </ul>
    </body>
    </html>
    """
    return render_template_string(html, logs=recent_logs)

if __name__ == "__main__":
    context = ('/home/iacpucpr/safecredential/cert.pem', '/home/iacpucpr/safecredential/key.pem')  # Certificado TLS
    app.run(host="0.0.0.0", port=5000, ssl_context=context)
