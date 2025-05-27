from flask import Flask, request, jsonify
import requests
import redis
import hmac
import hashlib
import pyotp

load_dotenv()

REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, password=REDIS_PASSWORD, db=0)

# Função para gerar HMAC para autenticação
def generate_hmac(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

@app.route('/request_access', methods=['POST'])
def request_access():
    data = request.json
    user_id = data.get("userID")
    otp_user_id = r.get("otp_user_id").decode()
    obfuscated_credential = r.get("obfuscated_credential").decode()
    hmac_signature = generate_hmac(otp_user_id, user_id)

    # Repassa a requisição para NIA_Client
    response = requests.post("https://localhost:5001/validate_and_access", json={
        "userID": user_id,
        "HMAC": hmac_signature,
        "credential": obfuscated_credential
    }, verify=False)
    return jsonify(response.json())

if __name__ == "__main__":
    app.run(port=5000, ssl_context=('cert.pem', 'key.pem'))