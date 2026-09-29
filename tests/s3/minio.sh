#!/bin/sh
# Starts a real MinIO server for the S3 backup tests and prints the
# environment the tests read. The bucket has versioning + object lock, and
# the node's credentials may put, get and list but never delete, as
# docs/operations.md recommends for production.
#
#   eval "$(tests/s3/minio.sh)"      # start and export
#   tests/s3/minio.sh stop
set -eu
NAME=od-minio
IMAGE=${OPENDEPLOY_MINIO_IMAGE:-cgr.dev/chainguard/minio:latest}
MC_IMAGE=${OPENDEPLOY_MC_IMAGE:-cgr.dev/chainguard/minio-client:latest}
PORT=${OPENDEPLOY_MINIO_PORT:-9000}
DIR=${OPENDEPLOY_S3_DIR:-${TMPDIR:-/tmp}/od-s3}
BUCKET=od-backups

if [ "${1:-}" = stop ]; then
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	exit 0
fi

mkdir -p "$DIR"
ROOT_USER=odroot
ROOT_PASS=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
NODE_USER=odnode
NODE_PASS=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:9000" \
	-e MINIO_ROOT_USER=$ROOT_USER -e MINIO_ROOT_PASSWORD="$ROOT_PASS" \
	"$IMAGE" server /data >/dev/null
i=0
until curl -fsS "http://127.0.0.1:$PORT/minio/health/ready" >/dev/null 2>&1; do
	i=$((i + 1))
	[ $i -lt 60 ] || { docker logs "$NAME" >&2; echo "minio did not start" >&2; exit 1; }
	sleep 1
done

cat >"$DIR/node-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:GetObjectRetention"], "Resource": ["arn:aws:s3:::$BUCKET/*"]},
    {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::$BUCKET"]}
  ]
}
EOF
mc() {
	docker run --rm --network host -v "$DIR:/cfg" -e MC_HOST_od="http://$ROOT_USER:$ROOT_PASS@127.0.0.1:$PORT" "$MC_IMAGE" "$@"
}
mc mb --with-lock od/$BUCKET >/dev/null
mc admin policy create od od-node /cfg/node-policy.json >/dev/null
mc admin user add od $NODE_USER "$NODE_PASS" >/dev/null
mc admin policy attach od od-node --user $NODE_USER >/dev/null

printf %s "$NODE_USER" >"$DIR/access_key"
printf %s "$NODE_PASS" >"$DIR/secret_key"
printf %s "$ROOT_USER" >"$DIR/root_access_key"
printf %s "$ROOT_PASS" >"$DIR/root_secret_key"
chmod 600 "$DIR"/*_key
cat <<EOF
export OPENDEPLOY_S3_ENDPOINT=http://127.0.0.1:$PORT
export OPENDEPLOY_S3_BUCKET=$BUCKET
export OPENDEPLOY_S3_ACCESS_KEY_FILE=$DIR/access_key
export OPENDEPLOY_S3_SECRET_KEY_FILE=$DIR/secret_key
export OPENDEPLOY_S3_ROOT_ACCESS_KEY_FILE=$DIR/root_access_key
export OPENDEPLOY_S3_ROOT_SECRET_KEY_FILE=$DIR/root_secret_key
EOF
