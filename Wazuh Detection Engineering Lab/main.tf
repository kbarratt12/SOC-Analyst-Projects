terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws" # Identifies the official plugin
      version = "~> 6.39.0"     # Locks the version to prevent breaks
    }
  }
}

provider "aws" {
  profile = "default"   # Uses the specifc AWS CLI profile
  region  = "us-east-1" # Deploys to Virginia
}

variable "my_ip" {
  description = "Public IP allowed to reach the dashboard and SSH, in CIDR form"
  type        = string
}

# Key Pair- to SSH in
resource "aws_key_pair" "wazuh_key" {
  key_name   = "wazuh-key"
  public_key = file("~/.ssh/wazuhkey.pub")
}

# Security Group
# Opening 8834 for nessus and 22 so I can ssh in
resource "aws_security_group" "wazuh_sg" {
  name        = "wazuh_sg"
  description = "Allow Wazuh UI and SSH"


  ingress {
    description = "Wazuh Agent TCP"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Wazuh Agent"
    from_port   = 1514
    to_port     = 1514
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Wazuh Agent Enrollment"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Wazuh Dashboard"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  egress {
    description = "Allow all outbound (needed for plugin downloads)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}


# EC2 Instance
# AMI: Ubuntu 22.04 LTS
# Instance type: t3.micro
# user_data: This script will run on boot so nessus will already be up and ready to go

resource "aws_instance" "wazuh" {
  ami                    = "ami-0c7217cdde317cfec"
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.wazuh_key.key_name
  vpc_security_group_ids = [aws_security_group.wazuh_sg.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }


  user_data = <<-EOF
    #!/bin/bash
    # update os and install wazuh
    apt-get update -y
    apt-get install -y curl
    curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
    bash ./wazuh-install.sh -a
  EOF

  tags = {
    Name = "wazuh-server"
  }

}

#OUTPUTS
output "wazuh_dashboard" {
  description = "Open this in your browser to access Wazuh"
  value       = "https://${aws_instance.wazuh.public_ip}"
}

output "ssh_command" {
  description = "Command to SSH into the interface"
  value       = "ssh -i ~/.ssh/wazuhkey ubuntu@${aws_instance.wazuh.public_ip}"
}
