output "region" {
  value = var.region
}
output "cluster_name" {
  value = aws_eks_cluster.main.name
}

/*
output "cluster_endpoint" {
  value = aws_eks_cluster.main.cluster_endpoint
}
*/
