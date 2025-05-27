import requests

# Função para solicitar acesso ao serviço via NIA_SafeCredential
def request_service(user_id):
    response = requests.post("https://localhost:5000/request_access", json={
        "userID": user_id
    }, verify=False)  # Em desenvolvimento, disable verificação de SSL
    return response.json()

# Exemplo de uso
user_id = "db0010"
response = request_service(user_id)
print("Resposta da NIA_SafeCredential:", response)
