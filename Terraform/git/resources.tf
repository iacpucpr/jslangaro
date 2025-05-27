# Configuração de redes
resource "docker_network" "network_1" {
  name = "network_1"
}

resource "docker_network" "network_2" {
  name = "network_2"
}

resource "docker_network" "network_3" {
  name = "network_3"
}

resource "docker_network" "network_4" {
  name = "network_4"
}

resource "docker_network" "network_6" {
  name = "network_6"
}

resource "docker_network" "network_7" {
  name = "network_7"
}
# Nginx Container
resource "docker_image" "nginx" {
  name         = "nginx:latest"
  keep_locally = false
}

resource "docker_container" "nginx" {
  image        = docker_image.nginx.image_id
  name         = "nginx"
  restart      = "always"
  network_mode = "network_1"
  ports {
    internal = 443
    external = "${var.nginx_https_port}"
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path      = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  
  # Provisionamento para configurar Proxy Reverso com HTTPS, instalar Twingate e criar usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec nginx bash -c "\
        apt-get update && \
        apt-get install -y openssh-server curl openssl && \
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user} && \
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
        service ssh start && \
        mkdir -p /etc/nginx/ssl && \
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx-selfsigned.key -out /etc/nginx/ssl/nginx-selfsigned.crt -subj '/CN=nginx.local' && \
        echo 'server {
          listen 443 ssl;
          ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
          ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;
          location / {
              proxy_pass http://glpi:80;
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;
          }
        }' > /etc/nginx/conf.d/default.conf && \
        nginx -s reload"
    EOT
  }
}

# Container infra_backup
resource "docker_container" "infra_backup" {
  image             = "iacpucpr/infra_backup"
  name              = "infra_backup"
  must_run          = true
  network_mode      = "network_2"
  ports {
    internal = 22
    external = 222
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path      = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  command = ["tail", "-f", "/dev/null"]

  # Provisionamento para instalar SSH, Twingate e criar o usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec infra_backup bash -c "\
        apt-get update && \
        apt-get install -y openssh-server curl && \
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user} && \
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
        service ssh start"
    EOT
  }
}

# Container infra_nas (Ubuntu)
resource "docker_image" "ubuntu" {
  name = "ubuntu:latest"
}

resource "docker_container" "infra_nas" {
  image             = docker_image.ubuntu.image_id
  name              = "infra_nas"
  must_run          = true
  network_mode      = "network_3"
  ports {
    internal = 22
    external = 223
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  command = ["tail", "-f", "/dev/null"]

  # Provisionamento para instalar SSH, Twingate e criar o usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec infra_nas bash -c "\
        apt-get update && \
        apt-get install -y openssh-server curl && \
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user} && \
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
        service ssh start"
    EOT
  }
}

# Container credential_safe
resource "docker_container" "credential_safe" {
  image             = "iacpucpr/infra_ssh"
  name              = "credential_safe"
  must_run          = true
  network_mode      = "network_4"
  ports {
    internal = 22
    external = 221
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  command = ["tail", "-f", "/dev/null"]

  # Provisionamento para instalar SSH, Twingate e criar o usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec credential_safe bash -c "\
        apt-get update && \
        apt-get install -y openssh-server curl python3 python3-pip && \
        
        # Instalação de bibliotecas Python necessárias
        pip3 install flask hvac && \

        # Configuração de Redis com senha e hardening
        # sed -i 's/# requirepass .*/requirepass '${var.redis_password}/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command FLUSHDB ""/rename-command FLUSHDB ""/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command FLUSHALL ""/rename-command FLUSHALL ""/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command CONFIG ""/rename-command CONFIG ""/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command SHUTDOWN ""/rename-command SHUTDOWN ""/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command BGREWRITEAOF ""/rename-command BGREWRITEAOF ""/' /etc/redis/redis.conf && \
        # sed -i 's/# rename-command BGSAVE ""/rename-command BGSAVE ""/' /etc/redis/redis.conf && \
        # sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf && \
        # sed -i 's/^protected-mode no/protected-mode yes/' /etc/redis/redis.conf && \
        
        # # Reinicia o Redis com a nova configuração
        # systemctl restart redis && \

        # Configuração do SSH e instalação do Twingate
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user} && \
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
        service ssh start"
    EOT
  }
}
# Container GLPI com HTTPS
resource "docker_container" "glpi" {
  name         = "glpi"
  image        = "diouxx/glpi"
  restart      = "always"
  network_mode = "network_7"
  env = [
    "MARIADB_ROOT_PASSWORD=${var.glpi_db_root_password}",
    "MARIADB_DATABASE=glpidb",
    "MARIADB_USER=${var.glpi_db_user}",
    "MARIADB_PASSWORD=${var.glpi_db_password}"
  ]
  ports {
    internal = "443"
    external = "${var.glpi_https_port}"
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  
  # Provisionamento para configurar HTTPS, instalar Twingate e criar usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec glpi bash -c "\
        apt-get update && apt-get install -y openssl curl && \
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt -subj '/CN=glpi.local' && \
        echo '<VirtualHost *:443>
          SSLEngine on
          SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
          SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
          DocumentRoot /var/www/html
        </VirtualHost>' > /etc/apache2/sites-available/glpi-ssl.conf && \
        a2enmod ssl && a2ensite glpi-ssl && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user} && \
        service apache2 restart"
    EOT
  }
}

# Container MariaDB
resource "docker_container" "mariadb" {
  name         = "mariadb"
  image        = "mariadb:10.7"
  restart      = "always"
  network_mode = "network_6"
  env = [
    "MARIADB_ROOT_PASSWORD=${var.glpi_db_root_password}",
    "MARIADB_DATABASE=glpidb",
    "MARIADB_USER=${var.glpi_db_user}",
    "MARIADB_PASSWORD=${var.glpi_db_password}"
  ]
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }

  # Provisionamento para instalar Twingate e criar o usuário
  provisioner "local-exec" {
    command = <<EOT
      docker exec mariadb bash -c "\
        apt-get update && apt-get install -y curl && \
        curl -s https://binaries.twingate.com/client/setup.sh | bash && \
        useradd -m -p $(openssl passwd -1 '${var.ssh_user_password}') ${var.ssh_user}"
    EOT
  }
}

# Null resource para garantir execução ordenada
resource "null_resource" "run_random_docker_command" {
  triggers = {
    always_run = "${timestamp()}"
  }
}
