variable "twingate_login" {
  description = "Twingate Login NAME.twingate.com"
  type = string
  default  = "iacpucpr"
}
variable "twingate_api-token" {
  description = "Twingate API-TOKEN provided by twingate"
  type = string
  default  = "_D-CWFo2tegu2ttEbNaKMEt9yhUlHbpRjC4o9EkcwPPnO_7T4zIAWaS_bOzUUh4EhSNYhSsPExmfJUAhDwCkWKG2SQPY7NnfsByHIako8xxV-KhzTkoYOsq-z_7wLA0VEk3toA"
}
variable "private_subnet_cidr_blocks" {
  description = "Available cidr blocks for private subnets."
  type        = list(string)
  default     = [
    "172.20.0.2/30",
    "172.20.0.6/30",
    "172.20.0.10/30",
    "172.20.0.14/30",
    "172.20.0.18/30",
    "172.20.0.22/30",
    "172.20.0.26/30",
    "172.20.0.30/30",
  ]
}

# Variáveis de senha do Redis e do SSH
variable "redis_password" {
  description = "Senha para o Redis"
  type        = string
  default     = "@@iacpucpr2024@@"
}

# Porta HTTPS para o NGINX
variable "nginx_https_port" {
  description = "Porta HTTPS para o container NGINX"
  type        = number
  default     = 8000
}

# Variáveis para portas do GLPI e MariaDB

variable "glpi_https_port" {
  description = "Porta HTTPS para o container GLPI"
  type        = number
  default     = 443  # Valor padrão
}

variable "mariadb_port" {
  description = "Porta para o container MariaDB"
  type        = number
  default     = 3306
}

# Variáveis de autenticação
variable "glpi_db_root_password" {
  description = "Senha de root para o MariaDB no GLPI"
  type        = string
  default     = "@@iac2024@@"
}

variable "glpi_db_user" {
  description = "Nome de usuário para o MariaDB no GLPI"
  type        = string
  default     = "glpi_user"
}

variable "glpi_db_password" {
  description = "Senha do usuário glpi para o MariaDB no GLPI"
  type        = string
  default     = "@@iac2024@@"
}

# Variável para senha do usuário SSH em todos os containers
variable "ssh_user_password" {
  description = "Senha do usuário iacpucpr em todos os containers"
  type        = string
  default     = "@@iac2024@@"
}

# Variável para nome de usuário SSH nos containers
variable "ssh_user" {
  description = "Nome de usuário SSH em todos os containers"
  type        = string
  default     = "iacpucpr"
}
