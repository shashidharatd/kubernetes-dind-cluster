CNUM=${1:-0} #default is no increment for cluster 0
if ! [[ "$CNUM" =~ ^[0-9]+$ ]] ; then
   echo "Error: Expected an integer for cluster number"; exit 1
fi
CLUSTER_REGION="europe-west1"
#CLUSTER_REGION="us-central1"
CLUSTER_ZONE="europe-west1-b"
#CLUSTER_ZONE="us-central1-b"

CLUSTER_NAME="c$CNUM"
echo "$CLUSTER_NAME"
PORT_INCR=$(($CNUM * 100))
ETCD_PORT=$((4101 + $PORT_INCR))
APISERVER_PORT=$((6443 + $PORT_INCR))
APISERVER_INSECURE_PORT=$((8888 + $PORT_INCR))
DOCKER_IN_DOCKER_WORK_DIR="${DOCKER_IN_DOCKER_WORK_DIR}/${CLUSTER_NAME}"
