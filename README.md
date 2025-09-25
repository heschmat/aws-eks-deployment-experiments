# EKS Playground: Tetris, Mario, and 2048 Walk into a Cluster...

![Classic Games on the Cloud](assets/games-eks.png)

This guide walks you through deploying 3 classic games to Amazon EKS using the AWS Load Balancer Controller. It includes cluster creation, deploying the application, configuring ingress, and clean-up instructions.

## 1. Create the EKS Cluster

Provision the EKS cluster using `eksctl`. This process takes roughly 15 minutes.

```sh
# You must use the -f or --config-file flag to specify your YAML config.
eksctl create cluster -f ./k8s/cluster-config.yaml

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
#     spot: true
```

When you create the cluster with `eksctl`, it generates a *kubeconfig entry* for you.
By default, `eksctl` gives the context a human-friendly name in the form:
```sh
<iam-identity>@<cluster-name>.<region>.eksctl.io
```

AWS CLI, on the other hand, uses a different naming convention for the context:
```sh
arn:aws:eks:<region>:<account-id>:cluster/<cluster-name>
```

You can list the context and current context like so:
```
# List all contexts in your kubeconfig with:
# Note that the * marks your current context.
kubectl config get-contexts

# To get just the names:
kubectl config get-contexts -o name

# Note that both contexts point to the same underlying EKS cluster (games-cluster in us-east-1).


# You can always rename contexts in your kubeconfig with:
# best practice for context naming: <cluster-name>@<environment>.<region>
kubectl config rename-context OLD_NAME NEW_NAME

```

```sh
# Update kubeconfig to use the new cluster
# In general, this command adds the cluster credentials to the local ~/.kube/config.
# & lets you interact with the cluster using kubectl.
# N.B. you need to run `source .env` which acts as a centralized location for common environmental variables.
aws eks update-kubeconfig --name $CLUSTER_NAME --region $AWS_REGION

k config current-context

k get nodes -o wide
```

## 2. Deploy the Application and Ingress Resources

Apply the namespace, deployment, and service definitions:

```sh
cd k8s/manifests/
k apply -f namespace.yaml
k apply -f 2048_manifests.yaml
k apply -f tetris_manifests.yaml
```

To verify that so far the deployment is working just fine, we should be able to access the games via `<NODE_EXTERNAL_IP>:<NodePort>`.
In the corresponding manifests, we've set `nodePort` for the apps to 32321 and 32322.
Ensure the EC2 node's security group allows inbound traffic to the NodePort.
Access the app: `http://<NODE_PUBLIC_IP>:<NodePort>`

```sh
$ k get svc -n $APP_NS
NAME             TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
service-2048     NodePort   10.100.9.229     <none>        80:32321/TCP   19m
service-tetris   NodePort   10.100.120.140   <none>        80:32322/TCP   11m

# To get the external-ip of the node isntances:
$ k get nodes -o wide
```


Apply the ingress resource:

```sh
kubectl apply -f ingress.yaml
```

Check the status of the ingress:

```sh
kubectl get ing -n $APP_NS
```

> **Note:** Initially, there will be no public address for the ingress resource. The AWS Load Balancer Controller will create and configure a LoadBalancer based on the ingress specifications. We will create one shortly.


## 3. Configure IAM Roles for Service Accounts (IRSA)
Associate IAM OIDC Provider with the Cluster

```sh
# Set up an IAM OpenID Connect (OIDC) identity provider for your EKS cluster.
eksctl utils associate-iam-oidc-provider \
  --region $AWS_REGION \
  --cluster $CLUSTER_NAME \
  --approve
```
Why this is required?
- The AWS Load Balancer Controller needs IAM permissions (to create/manage ALBs, Target Groups, security groups, etc.).
- Best practice (and AWS's recommended method) is to use IAM Roles for Service Accounts (IRSA).
- IRSA depends on the OIDC provider being set up — it lets Kubernetes service accounts in your cluster assume IAM roles securely.


## 4. Create Service Account with IAM Role

```sh
# AWS provides a ready-made IAM policy JSON (iam_policy.json) with all required permissions (ELB, Target Groups, Security Groups, etc.).
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.11.0/docs/install/iam_policy.json

# Create IAM Policy
aws iam create-policy \
  --policy-name AWSLBControllerIAMPolicy \
  --policy-document file://iam_policy.json

# Remove the policy document:
rm iam_policy.json

# Use eksctl to bind the above policy to a Kubernetes service account:
IAM_SA_NAME=aws-lb-ctl

eksctl create iamserviceaccount \
  --cluster $CLUSTER_NAME \
  --namespace kube-system \
  --name $IAM_SA_NAME \
  --role-name AWSEKSLBControllerRole \
  --attach-policy-arn arn:aws:iam::$AWS_ACC_ID:policy/AWSLBControllerIAMPolicy \
  --approve
```

## 5. Install AWS Load Balancer Controller Using Helm
Add and Update Helm Repository

```sh
helm repo add eks https://aws.github.io/eks-charts
helm repo update eks
```

Get the VPC ID for the Cluster & install the controller

```sh
VPC_ID=$(aws eks describe-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query "cluster.resourcesVpcConfig.vpcId" \
  --output text)

echo $VPC_ID

# Deploy the AWS Load Balancer Controller
helm install aws-lb-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=$CLUSTER_NAME \
  --set serviceAccount.create=false \
  --set serviceAccount.name=$IAM_SA_NAME \
  --set region=$AWS_REGION \
  --set vpcId=$VPC_ID
```

## 6. Verify Load Balancer and Access the Application

### Check the Controller Pods

```sh
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

### Retrieve the Ingress Address

```sh
kubectl get ing -n $APP_NS
```

As we're just testing and don't necessarily want to incur additional costs by buying a domain, we can use free DNS services - such as `nip.io` or `sslip.io` - that map IPs directly into domain names.

For that we need to re-configure to the ingress resource with the EXTERNAL IP of the ALB's DNS (ADDRESS field in the command above).

```sh
# Get the EXTERNAL IP of the ALB:
nslookup <ALB_DNS_name>


cat k8s/manifests/ingress.yaml | grep nip.io
#  - host: tetris.<ALB_EXTERNAL_IP>.nip.io
#  - host: 2048.<ALB_EXTERNAL_IP>.nip.io


# re-configure the ingress
kubectl apply -f k8s/manifests/ingress.yaml
```

Now, the app should be accessible via the address specified in the `host` in ingress.

## 7. (Optional) Accessing via NodePort

In the meantime you can access the service via NodePort. The 2048 app has already configured the service as NodePort. So you can access the app via `<NODE_EXT_IP>:<NodePort>`.
For the tetris game, we've setup the service as `CluserIP`. As we're testing, we can **patch** it to a `NodePort` service.

```sh
# This command will update the service type from ClusterIP to NodePort. The service will be exposed on a port on each node in the cluster.
# By default, Kubernetes will automatically assign a port within the NodePort range (30000-32767).
kubectl patch svc <service-name> -p '{"spec": {"type": "NodePort"}}'

# If you want to specify a specific port, you can include it in the patch:
kubectl patch svc service-tetris -n $APP_NS -p '{"spec": {"type": "NodePort", "ports": [{"port": 80, "targetPort": 8080, "nodePort": 30001}]}}'

# N.B. Don't forget to add a rule in the security group that allows traffic on port 30001. Or whatever NodePort you've chosen.
```

## 8. Clean Up Resources

To avoid incurring charges, delete the EKS cluster once you’re done:

```sh
eksctl delete cluster --config-file=k8s/cluster-config.yaml
```

> **Note:** After deletion, visit the CloudFormation console and manually remove any residual stacks associated with the cluster.
