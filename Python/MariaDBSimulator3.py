from flask import Flask, request, jsonify, render_template_string
import logging
import ssl
import time
from datetime import datetime

app = Flask(__name__)

# Configuração do logging
#logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.basicConfig(level=logging.CRITICAL)  # Desativa logs INFO e WARNING na console

# Lista para armazenar logs recentes
recent_logs = []

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"{timestamp} - {message}"
    recent_logs.append(message)
    if len(recent_logs) > 20:  # Limita a lista a 20 logs
        recent_logs.pop(0)
    logging.info(message)

@app.route('/mariadb/connect', methods=['POST'])
def connect():
    try:
        data = request.get_json()
        db_username = data.get("username")
        db_password = data.get("password")

        # Combina username e password em um formato unificado
        credential = f"{db_username}:{db_password}"

        # Registra apenas o log da credential
        log_message(f"Credential de acesso ao DB: {credential}")

        # Simula validação e sucesso
        return jsonify({"status": "success", "message": "Conexão simulada com sucesso ao MariaDB"}), 200

    except Exception as e:
        log_message(f"Erro ao processar conexão simulada: {e}")
        return jsonify({"status": "error", "message": "Erro ao processar conexão simulada"}), 500

@app.route('/status', methods=['GET'])
def status():
    log_message("Consulta ao status do MariaDB Simulator.")
    return jsonify({"status": "MariaDB Simulator está funcionando."})

@app.route('/debug', methods=['GET'])
def debug():
    log_message("Consulta ao endpoint de debug.")
    return jsonify({"debug_info": "Simulador do MariaDB, pronto para receber conexões."})

@app.route('/logs', methods=['GET'])
def logs():
    log_message("Consulta aos logs recentes.")
    return jsonify({"logs": recent_logs})

@app.route('/admin', methods=['GET'])
def admin():
    html = """
    <html>
    <head><title>Admin - MariaDBSimulator</title></head>
    <body>
        <h1>Administração - MariaDB Simulator</h1>
        <p>Status: Funcionando</p>
        <h2>Logs Recentes</h2>
        <ul>
            {% for log in logs %}
                <li>{{ log }}</li>
            {% endfor %}
        </ul>
        <h2>Teste de Conexão</h2>
        <form action="/mariadb/connect" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Testar Conexão">
        </form>
    </body>
    </html>
    """
    return render_template_string(html, logs=recent_logs)

if __name__ == "__main__":
    # Servidor rodando em HTTP na porta 3306
    app.run(host="0.0.0.0", port=3306)

