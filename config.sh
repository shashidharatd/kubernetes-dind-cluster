# Apiserver host name used by the kubeconfig for the kubectl
APISERVER_ADDRESS=${APISERVER_ADDRESS:-$(ifconfig docker0 2>/dev/null|awk '/inet addr:/ {print $2}'|sed 's/addr://')}

# Path to directory on the host to use as the root for multiple docker volumes.
# ${DOCKER_IN_DOCKER_WORK_DIR}/log - storage of component logs (written on deploy failure)
# ${DOCKER_IN_DOCKER_WORK_DIR}/auth - storage of SSL certs/keys/tokens
# If using docker-machine or boot2docker, should be under /Users (which is mounted from the host into the docker vm).
# If running in a container, $HOME should be resolved outside of the container.
DOCKER_IN_DOCKER_WORK_DIR="${DOCKER_IN_DOCKER_WORK_DIR:-${HOME}/tmp/kubernetes-dind}"

# Arguments to pass to docker-engine running on the kubernetes-dind containers.
DOCKER_DAEMON_ARGS="${DOCKER_DAEMON_ARGS:---log-level=error}"

# Skip rebuilding the involved docker containers on kube-up.sh.
DOCKER_IN_DOCKER_SKIP_BUILD="${DOCKER_IN_DOCKER_SKIP_BUILD:-false}"

# Optional: Deploy cluster web interface.
ENABLE_CLUSTER_UI="${ENABLE_CLUSTER_UI:-false}"

# Optional: Deploy cluster DNS.
ENABLE_CLUSTER_DNS="${ENABLE_CLUSTER_DNS:-true}"
DNS_SERVER_IP="${DNS_SERVER_IP:-10.0.0.10}"
DNS_DOMAIN="${DNS_DOMAIN:-cluster.local}"
DNS_REPLICAS="${DNS_REPLICAS:-1}"

# Timeout (in seconds) to wait for each addon to come up
DOCKER_IN_DOCKER_ADDON_TIMEOUT="${DOCKER_IN_DOCKER_ADDON_TIMEOUT:-180}"

# Apiserver service IP
APISERVER_SERVICE_IP="${APISERVER_SERVICE_IP:-10.0.0.1}"
SERVICE_CIDR="${SERVICE_CIDR:-${APISERVER_SERVICE_IP}/24}"

# Number of nodes
NUM_NODES=${NUM_NODES:-1}

# Private registry to pull kubernetes images while not connected to internet
USE_PRIVATE_REGISTRY="true"
PRIVATE_REGISTRY=${PRIVATE_REGISTRY:-172.17.0.1:5000}

if [[ "${USE_PRIVATE_REGISTRY}" == "true" ]]; then
  DOCKER_DAEMON_ARGS="${DOCKER_DAEMON_ARGS} --insecure-registry ${PRIVATE_REGISTRY}"
fi

# Node labels indicating cluster Region & Zones
CLUSTER_REGION="asia-east1"
CLUSTER_ZONE="asia-east1-a"

CLUSTER_NAME="c1"
ETCD_PORT=4001
APISERVER_PORT=6443
APISERVER_INSECURE_PORT=8888
