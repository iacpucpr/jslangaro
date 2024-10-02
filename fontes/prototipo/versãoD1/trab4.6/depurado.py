try:
    # Tenta executar o bloco de código dentro do "try". Se ocorrer uma exceção, ela será tratada.

    totp = pyotp.TOTP(base64.b32encode(''.join(poetry_lines).encode()).decode())
    # Cria um objeto TOTP usando a biblioteca pyotp, gerando uma chave baseada na codificação Base32
    # de uma string combinada de 'poetry_lines', que são as linhas de um texto (por exemplo, uma poesia).

    otp = totp.now()
    # Gera o OTP (One-Time Password) atual baseado no tempo.

    print(f"Generated OTP: {otp}")
    # Exibe o OTP gerado.

    otp_hash = hash_otp(otp)
    # Aplica a função 'hash_otp' ao OTP para gerar um hash do OTP, possivelmente para uma camada extra de segurança.

    response = send_otp_and_counter(secure_conn, otp_hash, client_counter)
    # Envia o hash do OTP e o contador do cliente (client_counter) para o servidor usando uma conexão segura (secure_conn).
    # O servidor deve validar o OTP e o contador.

    print(f"Server response: {response}")
    # Exibe a resposta recebida do servidor.

    if response != "OTP Valid":
        # Verifica se a resposta do servidor não é "OTP Valid" (o que significa que a validação do OTP falhou).
        print("OTP validation failed. Exiting.")
        # Exibe uma mensagem informando que a validação do OTP falhou.
        return
        # Encerra a execução da função, saindo do fluxo atual.

    seed = generate_seed(poetry_lines, otp)
    # Gera uma semente (seed) usando as linhas da poesia e o OTP atual. Isso é usado para criar um HOTP.

    hotp = pyotp.HOTP(base64.b32encode(seed.encode()).decode())
    # Cria um objeto HOTP (Hash-based One-Time Password) usando a semente gerada. A semente é codificada em Base32.

    current_hotp = hotp.at(client_counter)
    # Gera o HOTP atual com base no contador do cliente (client_counter).

    print(f"Generated HOTP: {current_hotp}")
    # Exibe o HOTP gerado.

    secure_conn.send(b"Request Credential")
    # Envia uma solicitação ao servidor pedindo a credencial ofuscada (obfuscated credential).

    obfuscated_cred = secure_conn.recv(1024).decode()
    # Recebe a credencial ofuscada do servidor (até 1024 bytes), e decodifica de bytes para string.

    print(f"Received obfuscated credential: {obfuscated_cred}")
    # Exibe a credencial ofuscada recebida do servidor.

    client_counter += 1
    # Incrementa o contador do cliente para manter a sincronização entre cliente e servidor.

    print(f"Updated client counter: {client_counter}")
    # Exibe o valor atualizado do contador do cliente.
