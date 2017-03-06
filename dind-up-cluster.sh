#!/bin/bash

# Copyright 2016 The Kubernetes Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

if [ $(uname) = Darwin ]; then
  readlinkf(){ perl -MCwd -e 'print Cwd::abs_path shift' "$1";}
else
  readlinkf(){ readlink -f "$1"; }
fi
DIND_ROOT="$(cd $(dirname "$(readlinkf "${BASH_SOURCE}")"); pwd)"

if [ ! -f cluster/kubectl.sh ]; then
  echo "$0 must be called from the Kubernetes repository root directory" 1>&2
  exit 1
fi

# Execute a docker-compose command with the default environment and compose file.
function dind::docker_compose {
  local params="$@"

  # All vars required to be set
  declare -a env_vars=(
    "DOCKER_IN_DOCKER_WORK_DIR"
    "APISERVER_SERVICE_IP"
    "SERVICE_CIDR"
    "DNS_SERVER_IP"
    "DNS_DOMAIN"
    "DOCKER_DAEMON_ARGS"
    "CLUSTER_REGION"
    "CLUSTER_ZONE"
    "ETCD_PORT"
    "APISERVER_PORT"
    "APISERVER_INSECURE_PORT"
  )

  (
    for var_name in "${env_vars[@]}"; do
      export ${var_name}="${!var_name}"
    done

    export DOCKER_IN_DOCKER_STORAGE_DIR=${DOCKER_IN_DOCKER_STORAGE_DIR:-${DOCKER_IN_DOCKER_WORK_DIR}/storage}

    docker-compose -p ${CLUSTER_NAME} -f "${DIND_ROOT}/docker-compose.yml" ${params}
  )
}

# Pull the images from a docker compose file, if they're not already cached.
# This avoid slow remote calls from `docker-compose pull` which delegates
# to `docker pull` which always hits the remote docker repo, even if the image
# is already cached.
function dind::docker_compose_lazy_pull {
  for img in $(grep '^\s*image:\s' "${DIND_ROOT}/docker-compose.yml" | sed 's/[ \t]*image:[ \t]*//'); do
    read repo tag <<<$(echo "${img} "| sed 's/:/ /')
    if [[ "${repo}" = k8s.io/kubernetes-dind* ]]; then
      continue
    fi
    if [ -z "${tag}" ]; then
      tag="latest"
    fi
    if ! docker images "${repo}" | awk '{print $2;}' | grep -q "${tag}"; then
      docker pull "${img}"
    fi
  done
}

# Generate kubeconfig data for the created cluster.
function dind::create-kubeconfig {
  local -r auth_dir="${DOCKER_IN_DOCKER_WORK_DIR}/auth"
  local kubectl="cluster/kubectl.sh"

  local name="federation-${CLUSTER_NAME}"

  local token="$(cut -d, -f1 ${auth_dir}/token-users)"
  "${kubectl}" config set-cluster ${name} --server="${KUBE_SERVER}" --certificate-authority="${auth_dir}/ca.pem" --embed-certs=true
  "${kubectl}" config set-context ${name} --cluster=${name} --user="${CLUSTER_NAME}-admin"
  "${kubectl}" config set-credentials ${CLUSTER_NAME}-admin --token="${token}"
  "${kubectl}" config use-context ${name} --cluster=${name}

   echo "Wrote config for ${name} context" 1>&2
}

# Must ensure that the following ENV vars are set
function dind::detect-master {
  KUBE_MASTER_IP="${APISERVER_ADDRESS}:${APISERVER_PORT}"
  KUBE_SERVER="https://${KUBE_MASTER_IP}"

  echo "KUBE_MASTER_IP: $KUBE_MASTER_IP" 1>&2
}

# Get minion IP addresses and store in KUBE_NODE_IP_ADDRESSES[]
function dind::detect-nodes {
  local docker_ids=$(docker ps --filter="name=${CLUSTER_NAME}_node" --quiet)
  if [ -z "${docker_ids}" ]; then
    echo "ERROR: node(s) not running" 1>&2
    return 1
  fi
  while read -r docker_id; do
    local minion_ip=$(docker inspect --format="{{.NetworkSettings.IPAddress}}" "${docker_id}")
    KUBE_NODE_IP_ADDRESSES+=("${minion_ip}")
  done <<< "$docker_ids"
  echo "KUBE_NODE_IP_ADDRESSES: [${KUBE_NODE_IP_ADDRESSES[*]}]" 1>&2
}

# Verify prereqs on host machine
function dind::verify-prereqs {
  dind::step "Verifying required commands"
  hash docker 2>/dev/null || { echo "Missing required command: docker" 1>&2; exit 1; }
  hash docker 2>/dev/null || { echo "Missing required command: docker-compose" 1>&2; exit 1; }
  docker run busybox grep -q -w -e "overlay\|aufs" /proc/filesystems || {
    echo "Missing required kernel filesystem support: overlay or aufs."
    echo "Run 'sudo modprobe overlay' or 'sudo modprobe aufs' (on Ubuntu) and try again."
    exit 1
  }
}

# Initialize
function dind::init_auth {
  local -r auth_dir="${DOCKER_IN_DOCKER_WORK_DIR}/auth"

  dind::step "Creating auth directory:" "${auth_dir}"
  mkdir -p "${auth_dir}"
  ! which selinuxenabled &>/dev/null || ! selinuxenabled 2>&1 || sudo chcon -Rt svirt_sandbox_file_t -l s0 "${auth_dir}"
  rm -rf "${auth_dir}"/*

  dind::step "Creating service accounts key:" "${auth_dir}/service-accounts-key.pem"
  openssl genrsa -out "${auth_dir}/service-accounts-key.pem" 2048 &>/dev/null

  local -r BASIC_PASSWORD="$(openssl rand -hex 16)"
  local -r MASTER_TOKEN="$(openssl rand -hex 32)"
  echo "${BASIC_PASSWORD},admin,admin" > ${auth_dir}/basic-users
  echo "${MASTER_TOKEN},${CLUSTER_NAME}-admin,${CLUSTER_NAME}-admin,system:masters" > ${auth_dir}/token-users
  dind::step "Creating credentials:" "admin:${BASIC_PASSWORD}, kubelet token"

  dind::step "Create TLS certs & keys:"
  docker run --rm -i  --entrypoint /bin/bash -v "${auth_dir}:/certs" -w /certs cfssl/cfssl:latest -ec "$(cat <<EOF
    cd /certs
    echo '{"CN":"CA","key":{"algo":"rsa","size":2048}}' | cfssl gencert -initca - | cfssljson -bare ca -
    echo '{"signing":{"default":{"expiry":"43800h","usages":["signing","key encipherment","server auth","client auth"]}}}' > ca-config.json
    echo '{"CN":"'apiserver'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | \
      cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -hostname=apiserver,kubernetes,kubernetes.default.svc.${DNS_DOMAIN},${APISERVER_SERVICE_IP},${APISERVER_ADDRESS} - | \
      cfssljson -bare apiserver
EOF
  )"
  cat "${auth_dir}/apiserver.pem" "${auth_dir}/ca.pem" > "${auth_dir}/apiserver-bundle.pem"
}

# Instantiate a kubernetes cluster.
function dind::kube-up {
  # Pull before `docker-compose up` to avoid timeouts caused by slow pulls during deployment.
  dind::step "Pulling docker images"
  dind::docker_compose_lazy_pull

  if [ "${DOCKER_IN_DOCKER_SKIP_BUILD}" != "true" ]; then
    dind::step "Building docker images"
    "${DIND_ROOT}/image/build.sh"
  fi

  dind::init_auth

  dind::step "Starting cluster ${CLUSTER_NAME}"
  dind::docker_compose up -d --force-recreate
  dind::step "Scaling cluster ${CLUSTER_NAME} to ${NUM_NODES} slaves"
  dind::docker_compose scale node=${NUM_NODES}

  dind::step -n "Waiting for https://${APISERVER_ADDRESS}:${APISERVER_PORT} to be healthy"
  while ! curl -o /dev/null -s --cacert ${DOCKER_IN_DOCKER_WORK_DIR}/auth/ca.pem https://${APISERVER_ADDRESS}:${APISERVER_PORT}; do
    sleep 1
    echo -n "."
  done
  echo

  dind::detect-master
  dind::detect-nodes
  dind::create-kubeconfig

  if [ "${ENABLE_CLUSTER_DNS}" == "true" ]; then
    dind::deploy-dns
    dind::await_ready "kube-dns" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}"
  fi
  if [ "${ENABLE_CLUSTER_UI}" == "true" ]; then
    dind::deploy-ui
    dind::await_ready "kubernetes-dashboard" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}"
  fi
}

function dind::deploy-dns {
  until $("cluster/kubectl.sh" get ns |grep "kube-system" >/dev/null 2>&1); do echo "waiting for 'kube-system' namespace to be ready"; sleep 2; done

  dind::step "Deploying kube-dns"
  "cluster/kubectl.sh" --namespace=kube-system create -f cluster/addons/dns/kubedns-sa.yaml
  "cluster/kubectl.sh" create -f <(
    for f in kubedns-controller.yaml kubedns-svc.yaml; do
      echo "---"
      eval "cat <<EOF
$(<"cluster/addons/dns/${f}.sed")
EOF
" 2>/dev/null
    done
  )
}

function dind::deploy-ui {
  dind::step "Deploying dashboard"
  "cluster/kubectl.sh" create -f "cluster/addons/dashboard/dashboard-controller.yaml"
  "cluster/kubectl.sh" create -f "cluster/addons/dashboard/dashboard-service.yaml"
}

function dind::validate-cluster {
  dind::step "Validating cluster ${CLUSTER_NAME}"

  # Do not validate cluster size. There will be zero k8s minions until a pod is created.
  # TODO(karlkfi): use componentstatuses or equivalent when it supports non-localhost core components

  # Validate immediate cluster reachability and responsiveness
  echo "KubeDNS: $(dind::addon_status 'kube-dns')"
  echo "Kubernetes Dashboard: $(dind::addon_status 'kubernetes-dashboard')"
}

# Delete a kubernetes cluster
function dind::kube-down {
  dind::step "Stopping cluster ${CLUSTER_NAME}"
  # Since restoring a stopped cluster is not yet supported, use the nuclear option
  dind::docker_compose kill
  dind::docker_compose rm -f -v
}

# Waits for a kube-system pod (of the provided name) to have the phase/status "Running".
function dind::await_ready {
  local pod_name="$1"
  local max_attempts="$2"
  local phase="Unknown"
  echo -n "${pod_name}: "
  local n=0
  until [ ${n} -ge ${max_attempts} ]; do
    phase=$(dind::addon_status "${pod_name}")
    if [ "${phase}" == "Running" ]; then
      break
    fi
    echo -n "."
    n=$[$n+1]
    sleep 1
  done
  echo "${phase}"
  return $([ "${phase}" == "Running" ]; echo $?)
}

# Prints the status of the kube-system pod specified
function dind::addon_status {
  local pod_name="$1"
  local kubectl="cluster/kubectl.sh"
  local phase=$("${kubectl}" get pods --namespace=kube-system -l k8s-app=${pod_name} -o template --template="{{(index .items 0).status.phase}}" 2>/dev/null)
  phase="${phase:-Unknown}"
  echo "${phase}"
}

function dind::step {
  local OPTS=""
  if [ "$1" = "-n" ]; then
    shift
    OPTS+="-n"
  fi
  GREEN="${1}"
  shift
  if [ -t 1 ] ; then
    echo -e ${OPTS} "\x1B[97m* \x1B[92m${GREEN}\x1B[39m $*" 1>&2
  else
    echo ${OPTS} "* ${GREEN} $*" 1>&2
  fi
}

source "${DIND_ROOT}/config.sh"

CLUSTER_CONFIG="${DIND_ROOT}/${1:-}.sh"
if [ -f "${CLUSTER_CONFIG}" ]; then
  source "${CLUSTER_CONFIG}"
fi

if [ $(basename "$0") = dind-up-cluster.sh ]; then
    dind::kube-up
    echo
    "cluster/kubectl.sh" cluster-info
    if [ "${2:-}" = "-w" ]; then
      trap "echo; dind::kube-down" INT
      echo
      echo "Press Ctrl-C to shutdown cluster"
      while true; do sleep 1; done
    fi
elif [ $(basename "$0") = dind-down-cluster.sh ]; then
  dind::kube-down
elif [ $(basename "$0") = dind-logs.sh ]; then
  dind::docker_compose logs -f $@
fi
