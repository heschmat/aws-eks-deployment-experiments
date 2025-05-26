data "aws_availability_zones" "azs" {
  state = "available"
}

module "eks-vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.17.0"

  name = "${var.cluster_name}-vpc"
  cidr = var.cidr_block

  azs             = [data.aws_availability_zones.azs.names[0], data.aws_availability_zones.azs.names[1]]
  private_subnets = [cidrsubnet(var.cidr_block, 8, 110), cidrsubnet(var.cidr_block, 8, 120)]
  public_subnets  = [cidrsubnet(var.cidr_block, 8, 10), cidrsubnet(var.cidr_block, 8, 20)]

  create_igw = true # Default is true

  enable_dns_hostnames = true # Default is true

  # nat_gateway configuration
  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false

  create_private_nat_gateway_route = true # Default is true

  tags = merge(
    var.tags,
    {
      # tell k8s “cluster game-2048 is allowed here”
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    }
  )

  public_subnet_tags = merge(
    var.tags,
    {
      "kubernetes.io/role/elb" = "1"
    }
  )

  private_subnet_tags = merge(
    var.tags,
    {
      "kubernetes.io/role/internal-elb" = "1"
    }
  )
}
