# Create EKS via Terraform

This guide shows how to provision an **Amazon EKS cluster** with Terraform, deploy a sample app, and expose it via **NodePort**, **LoadBalancer**, and **Ingress**.

⚠️ **Warning:** AWS resources incur costs. Remember to clean up after following this guide.

---

## 🚀 Prerequisites

* [Terraform](https://developer.hashicorp.com/terraform/downloads) (v1.5+)
* [kubectl](https://kubernetes.io/docs/tasks/tools/) (v1.25+)
* [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) (configured with credentials & default region)
* IAM permissions to create EKS clusters, VPCs, and associated resources

---

## 1. Provision EKS with Terraform

```bash
# This takes ~20 minutes
cd infra
terraform init
terraform apply --auto-approve
```

Update kubeconfig:

```bash
aws eks update-kubeconfig --region $(terraform output -raw region) \
  --name $(terraform output -raw cluster_name)
```

---

## 2. Deploy a Sample App (Nginx demo)

```bash
# This Deployment runs Pods from the image nginxdemos/hello, which listens on port 80.
kubectl create deploy hello --image=nginxdemos/hello
```

* Creates a **Deployment** named `hello`
* Default replicas: `1`
* Each pod runs `nginxdemos/hello`

Check pods:

```bash
kubectl get pods
```

---

## 3. Expose the App

There are 3 ways to expose apps in Kubernetes:

### 3.1 NodePort

```bash
kubectl expose deploy hello --port 80 --type NodePort
```

* Exposes app on a high port (30000–32767) of each node
* Example:

```bash
kubectl get svc hello
curl -I <NODE_EXT_IP>:<NodePort>
```

⚠️ Requires firewall/security group changes. Not recommended for production.

---

### 3.2 LoadBalancer

```bash
kubectl delete svc hello
kubectl expose deploy hello --port 80 --type LoadBalancer
```

* Provisions a cloud load balancer (AWS ELB)
* Example:

```bash
kubectl get svc hello
nslookup <LB_DNS_NAME>
curl -I <LB_IP>
```

✅ Good for production, but incurs AWS ELB costs.

---

### 3.3 Ingress

Ingress provides **HTTP/HTTPS routing (L7)**, useful for multiple services.

1. Install Ingress Controller:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.12.0/deploy/static/provider/cloud/deploy.yaml

kubectl get pods -n ingress-nginx
```

2. Patch service type:

```bash
kubectl patch svc hello -p '{"spec": {"type": "ClusterIP"}}'
```

3. Create Ingress resource:

```yaml
# hello-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hello-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx
  rules:
  - host: hello.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: hello
            port:
              number: 80
```

Apply:

```bash
kubectl apply -f hello-ingress.yaml

kubectl get ingress hello-ingress
```

Access:

```bash
curl -I <INGRESS_ADDRESS>
```

💡 Troubleshooting `503 Service Temporarily Unavailable3`: Ensure your service name and port match the Ingress spec
```sh
# If you haven't exposed the deployment.
# 👉 Without this Service, your Ingress would't know where to send requests.
# `type: ClusterIP` → internal-only Service, used by Ingress or other Pods.
kubectl expose deploy hello --port 80 --type ClusterIP
```

Running the above command, Kubernetes generates a Service YAML like this:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: hello
spec:
  selector:
    app: hello   # Matches the Deployment's Pods
  ports:
  - protocol: TCP
    port: 80      # Service port (what other Pods/Ingress use)
    targetPort: 80 # Container port in the Pod
  type: ClusterIP

```

---

## 🔑 Key Concepts

| Concept                | Role                                       |
| ---------------------- | ------------------------------------------ |
| Deployment             | Manages Pods                               |
| Service (ClusterIP)    | Internal-only access                       |
| Service (NodePort)     | Exposes via node ports (testing)           |
| Service (LoadBalancer) | Cloud-managed external access              |
| Ingress                | HTTP routing for one/multiple services     |
| Ingress Controller     | Implements Ingress resources (e.g., NGINX) |

---

## 🧹 Cleanup

### Delete Kubernetes resources

```bash
kubectl delete deploy hello
kubectl delete svc hello
kubectl delete ingress hello-ingress
```

### Tear down AWS resources

```bash
terraform destroy --auto-approve
```

⚠️ **DependencyViolation errors** may occur if AWS ELBs created by Kubernetes are not deleted before Terraform destroys the VPC. Delete k8s resources first. Terraform has no knowledge of those ELBs (they're created outside Terraform).

---

## ✅  Why Use Terraform for EKS?

* **Infrastructure as Code** → reproducible, auditable clusters
* **Multi-resource management** → VPC, IAM, RDS, S3, ALBs, etc. in one graph
* **Long-term maintenance** → track state, safely update resources
* **Multi-environment setups** → easily spin up dev/prod clusters
* **Compliance & Policies** → IAM, tagging, subnet isolation all codified

⚠️ **Tradeoffs:**

* Terraform is verbose and complex
* `eksctl` is faster for one-off clusters
* Hybrid approach: use `eksctl` for dev, Terraform for prod

---

✅ With this workflow, you can provision EKS clusters, deploy apps, expose them in multiple ways, and manage the full lifecycle with Terraform.
