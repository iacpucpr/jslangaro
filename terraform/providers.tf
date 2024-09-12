terraform {
  required_providers {
    docker = {
      source = "kreuzwerker/docker"
      version = "~> 3.0.2"
    }
    twingate = {
      source = "Twingate/twingate"
      version = "3.0.0"
    }
   }
}
provider "twingate" {
   api_token = var.twingate_api-token
   network   = var.twingate_login
}
provider "docker" {
  host = "unix:///var/run/docker.sock"
}