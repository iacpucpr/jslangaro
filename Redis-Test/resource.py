from flask import Flask, request, jsonify
import mysql.connector
import redis

load_dotenv()

REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, password=REDIS_PASSWORD, db=0)

# Configuração do Banco de Dados
db_config = {
    'host': 'localhost',
    'database': 'glpi',
    'user': '',  # Será preenchido com a credencial desofuscada
    'password': ''  # Será preenchido com a credencial desofuscada
}

# Função para se conectar ao banco e realizar uma consulta simples
def query_glpi_database(username, password):
    db_config['user'] = username
    db_config['password'] = password
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM glpi_users LIMIT 1;")  # Exemplo de consulta
        result = cursor.fetchall()
        return {"status": "Conexão bem-sucedida", "result": result}
    except mysql.connector.Error as err:
        return {"status": "Erro na conexão ao MariaDB", "error": str(err)}
    finally:
        if 'connection' in locals():
            connection.close()

# Endpoint para acesso ao recurso final (MariaDB)
@app.route('/access_resource', methods=['POST'])
def access_resource():
    data = request.json
    user_id = data.get("userID")
    credential = data.get("credential")  # Credencial desofuscada recebida da NIA_Client

    # Verifica se a credencial coincide com o que está no Redis
    stored_username = r.get("vault_username").decode()
    stored_password = r.get("vault_password").decode()

    if credential == f"{stored_username}{stored_password}":
        # Acesso ao MariaDB com a credencial válida
        response = query_glpi_database(stored_username, stored_password)
        return jsonify(response)
    else:
        return jsonify({"status": "Acesso negado: Credenciais inválidas"}), 403

if __name__ == "__main__":
    app.run(port=5002, ssl_context=('cert.pem', 'key.pem'))
