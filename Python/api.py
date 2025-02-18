import requests
import time
import logging
from threading import Thread
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# URL da API Safe Credential
safe_credential_url = "https://localhost:5000/access-mariadb"

# Variável global para controle do loop
running = True

def send_request():
    """
    Função que envia requisições continuamente para a API Safe Credential.
    """
    global running
    while running:
        try:
            logging.info("Enviando requisição para a API Safe Credential...")
            response = requests.post(safe_credential_url, json={}, verify=False)

            # Captura a resposta
            if response.status_code == 200:
                logging.info(f"Resposta da API Safe Credential: {response.json()}")
            else:
                logging.error(f"Erro na API Safe Credential: {response.status_code}, {response.text}")
        except Exception as e:
            logging.error(f"Erro ao enviar requisição: {e}")

        # Aguarda 1 minuto antes da próxima requisição
        time.sleep(60)

def start_requests():
    """
    Inicia o loop contínuo em uma thread separada.
    """
    global running
    running = True
    thread = Thread(target=send_request)
    thread.daemon = True
    thread.start()
    logging.info("Processo de requisições automáticas iniciado.")

def stop_requests():
    """
    Para o loop contínuo.
    """
    global running
    running = False
    logging.info("Processo de requisições automáticas interrompido.")

# Interface para controle via terminal
if __name__ == "__main__":
    print("Digite 'start' para iniciar ou 'stop' para interromper o envio de requisições.")
    while True:
        command = input("Comando: ").strip().lower()
        if command == "start":
            start_requests()
        elif command == "stop":
            stop_requests()
            break
        else:
            print("Comando inválido. Use 'start' ou 'stop'.")

