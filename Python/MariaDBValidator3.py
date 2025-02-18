from flask import Flask, request, jsonify, render_template_string
import hmac
import hashlib
import pyotp
import requests
import base64
import logging
import ssl
import urllib3
from datetime import datetime

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


def generate_shared_secret(file_path):
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            file_content = f.read()
        if len(lines) < 4:
            raise ValueError("O arquivo poetry.txt deve ter pelo menos 4 linhas.")

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
counter = 146578

@app.route('/validate', methods=['POST'])
def validate():
    global counter
    data = request.get_json()

    # Captura dos dados recebidos
    username = data.get("username")
    credential_obfuscated = data.get("credential_obfuscated")  # Mantendo consistência com o nome no SafeCredential
    otp = data.get("otp")
    received_hmac = data.get("hmac")

    log_message(f"Username recebido: {username}")
    log_message(f"Credential Ofuscada recebida: {credential_obfuscated}")
    log_message(f"HMAC Recebido: {received_hmac}")

    # Geração do TOTP para validação do HMAC
    totp = pyotp.TOTP(shared_secret)
    otp_totp = totp.now()
    expected_hmac = hmac.new(shared_secret.encode(), f"{username}:{otp_totp}".encode(), hashlib.sha256).hexdigest()

    log_message(f"TOTP Gerado: {otp_totp}")
    log_message(f"HMAC Gerado: {expected_hmac}")

    # Validação do HMAC
    if not hmac.compare_digest(received_hmac, expected_hmac):
        log_message("HMAC validation failed.")
        return jsonify({"valid": False, "error": "Invalid HMAC"}), 403
    else:
        log_message("HMAC validation successful.")

    # Verifica se há HOTP associado ao contador atual
    hotp = pyotp.HOTP(shared_secret)
    otp_hotp = hotp.at(counter)

    def xor_decrypt(data, key):
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key))

    # Desofusca a credencial recebida
    otp_str = str(hotp.at(counter)).zfill(len(credential_obfuscated))
    decrypted_password = xor_decrypt(credential_obfuscated, otp_str)

    log_message(f"Credential desofuscada: {decrypted_password}")

    # Envio ao simulador MariaDB
    mariadb_simulator_url = "http://127.0.0.1:3306/mariadb/connect"
    payload = {
        "username": username,
        "password": decrypted_password
    }

    try:
        response = requests.post(mariadb_simulator_url, json=payload, verify=False)
        if response.status_code == 200:
            log_message("Simulação de conexão com MariaDB bem-sucedida.")
            return jsonify({"valid": True}), 200
        else:
            error_message = response.json().get("message", "Erro desconhecido.")
            log_message(f"Falha na simulação de conexão com MariaDB: {error_message}")
            return jsonify({"valid": False, "error": error_message}), 403
    except requests.exceptions.RequestException as e:
        log_message(f"Erro ao conectar ao simulador MariaDB: {e}")
        return jsonify({"valid": False, "error": "Erro ao conectar ao simulador MariaDB"}), 500

@app.route('/logs', methods=['GET'])
def logs():
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
    app.run(host="0.0.0.0", port=5001, ssl_context=context)

