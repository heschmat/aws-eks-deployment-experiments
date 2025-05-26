variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

variable "cidr_block" {
  type    = string
  default = "10.10.0.0/16"
}

variable "tags" {
  type = map(string)
  default = {
    terraform  = "true"
    kubernetes = "game-2048"
  }
  description = "Tags to apply to all resources"
}

variable "cluster_name" {
  type    = string
  default = "game-2048"

}

variable "eks_version" {
  type        = string
  default     = "1.31"
  description = "EKS version"
}

