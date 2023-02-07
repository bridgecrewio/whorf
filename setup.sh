#!/usr/bin/env bash
# setup.sh
#
# Sets up the files required to deploy the Bridgecrew Checkov admission controller in a cluster

function Usage()
{
  echo "Illegal number of parameters, this script - $1"
  echo "Syntax: ./setup.sh cluster [bcapikey]"
}


if [ "$#" -eq 0 ] || [ "$#" -gt 2 ]; then
  Usage "$#"
  exit 1
fi

# the cluster (repository name)
cluster=$1

if [ "$#" -eq 2 ]; then
  # the Bridgecrew platform api key
  bcapikey=$2
fi


whorf_local=false
if [ -n "${WHORF_LOCAL}" ] && [ "${WHORF_LOCAL}" = "true" ]; then
  whorf_local=true
fi

set -euo pipefail

if $whorf_local ; then
  k8sdir="local"
  mkdir -p $k8sdir
else
  date=$(date '+%Y%m%d%H%M%S')
  echo "$date"

  codedir=bridgecrew$date
  mkdir "$codedir"
  k8sdir="$(dirname "$0")/${codedir}"
fi

certdir="$(mktemp -d)"

if $whorf_local ; then
  cp k8s/deployment.yaml "$k8sdir"/
  cp k8s/service.yaml "$k8sdir"/
  cp k8s/whorfconfig.yaml "$k8sdir"/
  cp k8s/checkovconfig.yaml "$k8sdir"/
  cp k8s/admissionconfiguration.yaml "$k8sdir"/
else
  # Get the files we need
  deployment=https://raw.githubusercontent.com/bridgecrewio/checkov/master/admissioncontroller/k8s/deployment.yaml
  configmap=https://raw.githubusercontent.com/bridgecrewio/checkov/master/admissioncontroller/k8s/checkovconfig.yaml
  admissionregistration=https://raw.githubusercontent.com/bridgecrewio/checkov/master/admissioncontroller/k8s/admissionconfiguration.yaml
  service=https://raw.githubusercontent.com/bridgecrewio/checkov/master/admissioncontroller/k8s/service.yaml
  whorfconfigmap=https://raw.githubusercontent.com/bridgecrewio/checkov/master/admissioncontroller/k8s/whorfconfig.yaml

  curl -o "$k8sdir"/deployment.yaml $deployment
  curl -o "$k8sdir"/service.yaml $service
  curl -o "$k8sdir"/whorfconfig.yaml $whorfconfigmap
  
  # Pop these into the temp directory as we'll make some customisations pipe in into the k8s dir
  curl -o "$certdir"/checkovconfig.yaml $configmap
  curl -o "$certdir"/admissionconfiguration.yaml $admissionregistration
fi

# the namespace
ns=bridgecrew
kubectl create ns $ns --dry-run=client -o yaml \
  | sed  '/^metadata:/p; s/^metadata:/  labels: {"whorf.ignore":"true"}/' > "$k8sdir"/namespace.yaml

# Generate keys into a temporary directory.
echo "Generating TLS certs ..."
openssl req -x509 -sha256 -newkey rsa:2048 -keyout "$certdir"/webhook.key -out "$certdir"/webhook.crt -days 1024 -nodes \
  -extensions SAN \
  -config <(cat /etc/ssl/openssl.cnf \
          <(printf "[SAN]\nsubjectAltName=DNS.1:validate.$ns.svc"))

kubectl create secret generic admission-tls -n bridgecrew --type=Opaque --from-file="$certdir"/webhook.key \
  --from-file="$certdir"/webhook.crt --dry-run=client -o yaml > "$k8sdir"/secret.yaml


# Create the `bridgecrew` namespace.
echo "Creating Kubernetes objects ..."

# Read the PEM-encoded CA certificate, base64 encode it, and replace the `${CA_PEM_B64}` placeholder in the YAML
# template with it. Then, create the Kubernetes resources.
ca_pem_b64="$(openssl base64 -A <"${certdir}/webhook.crt")"
sed -e 's@${CA_PEM_B64}@'"$ca_pem_b64"'@g' "${certdir}/admissionconfiguration.yaml"  > "${k8sdir}/admissionconfiguration.yaml"

# Change the cluster in the checkovconfig to our cluster name
sed -e 's@cluster@'"$cluster"'@g' "${certdir}/checkovconfig.yaml"  > "${k8sdir}/checkovconfig.yaml"

# Apply everything in the bridgecrew directory in the correct order
kubectl apply -f "$k8sdir/namespace.yaml"
kubectl apply -f "$k8sdir/secret.yaml"
kubectl apply -f "$k8sdir/checkovconfig.yaml"
kubectl apply -f "$k8sdir/whorfconfig.yaml"
kubectl apply -f "$k8sdir/service.yaml"
kubectl apply -f "$k8sdir/deployment.yaml"
kubectl apply -f "$k8sdir/admissionconfiguration.yaml"

if [ -z "$bcapikey" ]; then
  kubectl create secret generic bridgecrew-secret \
     --from-literal=credentials="$bcapikey" -n bridgecrew --dry-run=client -o yaml > "$k8sdir/secret-apikey.yaml"
  kubectl apply -f "$k8sdir/secret-apikey.yaml"
fi

# Delete the key directory to prevent abuse (DO NOT USE THESE KEYS ANYWHERE ELSE).
if ! $whorf_local ; then
  rm -rf "$certdir"
fi

# Wait for the deployment to be available
echo "Waiting for deployment to be Ready..."
kubectl wait --for=condition=Available deployment/validation-webhook --timeout=60s -n bridgecrew
echo "The webhook server has been deployed and configured!"

