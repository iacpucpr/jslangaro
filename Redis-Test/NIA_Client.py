from flask import Flask, request, jsonify
import base64
import hmac
import hashlib
import redis
import pyotp
import requests

load_dotenv()

REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, password=REDIS_PASSWORD, db=0)

# Função para validar HMAC
def validate_hmac(received_hmac, otp_user_id, user_id):
    expected_hmac = hmac.new(otp_user_id.encode(), user_id.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_hmac, expected_hmac)

# Função para desofuscar a credencial
def deobfuscate_credential(ofuscated_data, hotp):
    ofuscated_bytes = base64.b64decode(ofuscated_data)
    original_bytes = bytearray()
    for i in range(len(ofuscated_bytes)):
        original_bytes.append(ofuscated_bytes[i] ^ ord(hotp[i % len(hotp)]))
    return original_bytes.decode('utf-8')

@app.route('/validate_and_access', methods=['POST'])
def validate_and_access():
    data = request.json
    user_id = data.get("userID")
    received_hmac = data.get("HMAC")
    obfuscated_credential = data.get("credential")
    otp_user_id = r.get("otp_user_id").decode()
    hotp_user_id = r.get("hotp_user_id").decode()

    if not validate_hmac(received_hmac, otp_user_id, user_id):
        return jsonify({"status": "Falha na autenticação: HMAC inválido"}), 403

    decoded_credential = deobfuscate_credential(obfuscated_credential, hotp_user_id)
    stored_username = r.get("vault_username").decode()
    stored_password = r.get("vault_password").decode()
    credential = f"{stored_username}{stored_password}"

    # Envia a credencial desofuscada ao recurso final (MariaDB)
    response = requests.post("https://localhost:5002/access_resource", json={
        "userID": user_id,
        "credential": credential
    }, verify=False)
    return jsonify(response.json())

if __name__ == "__main__":
    app.run(port=5001, ssl_context=('cert.pem', 'key.pem'))