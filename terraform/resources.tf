resource "twingate_remote_network" "twingate_net" {
  name = "twingate_net"
}
resource "docker_network" "twingate_net" {
  name = "twingate_net"
}
resource "docker_network" "network_1" {
  name = "network_1"
  ipam_config {
    subnet = "172.20.0.4/30"
  }
}
resource "docker_network" "network_2" {
  name = "network_2"
  ipam_config {
    subnet = "172.20.0.8/30"
  }
}
resource "docker_network" "network_3" {
  name = "network_3"
  ipam_config {
    subnet = "172.20.0.12/30"
  }
}
resource "docker_network" "network_4" {
  name = "network_4"
  ipam_config {
    subnet = "172.20.0.16/30"
  }
}
resource "docker_network" "network_5" {
  name = "network_5"
  ipam_config {
    subnet = "172.20.0.20/30"
  }
}
resource "docker_network" "network_6" {
  name = "network_6"
  ipam_config {
    subnet = "172.20.0.24/30"
  }
}
resource "docker_network" "network_7" {
  name = "network_7"
  ipam_config {
    subnet = "172.20.0.28/30"
  }
}
resource "docker_image" "nginx" {
  name         = "nginx:latest"
  keep_locally = false
}
resource "docker_container" "nginx" {
  image = docker_image.nginx.image_id
  name  = "nginx"
  restart = "always"
  network_mode = "network_1"
  ports {
    internal = 80
    external = 8000
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
}
#resource "docker_image" "infra_backup" {
#  name = "ubuntu:latest"
#}
# Creating a Docker Container using the latest ubuntu image.
resource "docker_container" "infra_backup" {
  image             = "iacpucpr/infra_backup:latest"
  name              = "infra_backup"
  must_run          = true
  publish_all_ports = true
  network_mode = "network_2"
  ports {
    internal = 22
    external = 222
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
  command = [
    "tail",
    "-f",
    "/dev/null"
  ]
}
# Creating a Docker Image ubuntu with the latest as the Tag.
#resource "docker_image" "SSH-server" {
#  name = "ubuntu:latest"
#}
# Creating a Docker Container using the latest ubuntu image.
resource "docker_container" "infra_ssh" {
  image             = "iacpucpr/infra_ssh"
  name              = "infra_ssh"
  must_run          = true
  command = [
    "tail",
    "-f",
    "/dev/null"
  ]
  network_mode = "network_3"
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
}
resource "docker_container" "glpi" {
  name  = "glpi"
  image = "diouxx/glpi"
  restart = "always"
  network_mode = "network_7"
  env = [
    "MARIADB_ROOT_PASSWORD=password",
    "MARIADB_DATABASE=glpidb",
    "MARIADB_USER=glpi_user",
    "MARIADB_PASSWORD=glpi"
  ]
  ports {
    internal = "80"
    external = "${var.glpi_port}"
  }
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
}
resource "docker_container" "mariadb" {
  name  = "mariadb"
  image = "mariadb:10.7"
  restart = "always"
  network_mode = "network_6"
  env = [
    "MARIADB_ROOT_PASSWORD=password",
    "MARIADB_DATABASE=glpidb",
    "MARIADB_USER=glpi_user",
    "MARIADB_PASSWORD=glpi"
  ]
  capabilities {
    add = ["NET_ADMIN"]
  }
  devices {
    host_path = "/dev/net/tun"
    container_path = "/dev/net/tun"
  }
}
#Recurso de execucao local para invocar o script Bash
resource "null_resource" "run_random_docker_command" {
  triggers = {
    always_run = "${timestamp()}"
  }
}