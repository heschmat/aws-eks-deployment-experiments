# Deploying a Sample Application to Amazon EKS

This guide walks you through deploying a simple 2048 game application to Amazon EKS using the AWS Load Balancer Controller. It includes cluster creation, deploying the application, configuring ingress, and clean-up instructions.

## 1. Download Application Manifest

The 2048 application manifest is provided by the AWS Load Balancer Controller examples.

```sh
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.5.4/docs/examples/2048/2048_full.yaml

# or:
wget https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.5.4/docs/examples/2048/2048_full.yaml
```

## 2. Create the EKS Cluster

Provision the EKS cluster using `eksctl`. This process may take approximately 15 minutes.

```sh
eksctl create cluster -f cluster-config.yaml

# cluster-config.yaml -------------
# apiVersion: eksctl.io/v1alpha5
# kind: ClusterConfig

# metadata:
#   name: cluster-2048
#   region: us-east-1

# nodeGroups:
#   - name: nodes-2048
#     instanceType: t3.small
#     desiredCapacity: 2
#     minSize: 2
#     maxSize: 4
```

This command also updates your `kubeconfig` automatically.

Verify that your context is correctly set:

```sh
kubectl config current-context

kubectl get nodes
```

## 3. Deploy the Application and Ingress Resources

Apply the namespace, deployment, and service definitions:

```sh
kubectl apply -f ns-deploy-svc.yaml
```

Apply the ingress resource:

```sh
kubectl apply -f ingress.yaml
```

Check the status of the ingress:

```sh
kubectl get ing -n game-2048
```

> **Note:** Initially, there will be no public address for the ingress resource. The AWS Load Balancer Controller will create and configure a LoadBalancer based on the ingress specifications. We will create one shortly.


## 4. Configure IAM Roles for Service Accounts (IRSA)

### Download IAM Policy for AWS Load Balancer Controller

```sh
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.11.0/docs/install/iam_policy.json
```

### Create IAM Policy

```sh
aws iam create-policy \
  --policy-name AWSLBControllerIAMPolicy \
  --policy-document file://iam_policy.json
```

### Associate IAM OIDC Provider with the Cluster

```sh
eksctl utils associate-iam-oidc-provider \
  --region us-east-1 \
  --cluster cluster-2048 \
  --approve
```

### Create Service Account with IAM Role

Replace the policy ARN with the ARN returned from the previous step:

```sh
eksctl create iamserviceaccount \
  --cluster cluster-2048 \
  --namespace kube-system \
  --name aws-lb-ctl \
  --role-name AWSEKSLBControllerRole \
  --attach-policy-arn arn:aws:iam::134858049015:policy/AWSLBControllerIAMPolicy \
  --approve
```

## 5. Install AWS Load Balancer Controller Using Helm

### Add and Update Helm Repository

```sh
helm repo add eks https://aws.github.io/eks-charts
helm repo update eks
```

### Get the VPC ID for the Cluster

```sh
aws eks describe-cluster \
  --name cluster-2048 \
  --region us-east-1 \
  --query "cluster.resourcesVpcConfig.vpcId" \
  --output text
```

### Install the Controller

Substitute `vpc-XXXXXXXX` with the actual VPC ID:

```sh
helm install aws-lb-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=cluster-2048 \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-lb-ctl \
  --set region=us-east-1 \
  --set vpcId=vpc-XXXXXXXX
```

## 6. Verify Load Balancer and Access the Application

### Check the Controller Pods

```sh
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

### Retrieve the Ingress Address

```sh
kubectl get ing -n game-2048
```

Example output:

```sh
NAME           CLASS   HOSTS   ADDRESS                                                                   PORTS   AGE
ingress-2048   alb     *       k8s-game2048-ingress2-c6da6cd415-1199018295.us-east-1.elb.amazonaws.com   80      16m
```
Now you can access the app via the above address, this is the same as the DNS of the ALB. You have to wait for the created ALB - accessible via the EC2 tab - to become active.


## 7. (Optional) Accessing via NodePort

In the meantime you can access the service via NodePort:

1. Retrieve the EC2 public IP of a worker node:

```sh
kubectl get nodes -o wide
```

2. Retrieve the NodePort from the service:

```sh
kubectl get svc -n game-2048
```

3. Ensure the EC2 node's security group allows inbound traffic to the NodePort.

Access the app: `http://<EC2_PUBLIC_IP>:<NODE_PORT>`

## 8. Clean Up Resources

To avoid incurring charges, delete the EKS cluster once you’re done:

```sh
eksctl delete cluster --config-file=cluster-config.yaml
```

> **Note:** After deletion, visit the CloudFormation console and manually remove any residual stacks associated with the cluster.
