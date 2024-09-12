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
variable glpi_port {
  default = "8080"
}