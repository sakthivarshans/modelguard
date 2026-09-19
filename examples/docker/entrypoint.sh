#!/bin/sh
# Verify the model at container start; only then run the real command.
#
# Fails closed: any problem (missing trust root, verification failure,
# missing files) stops the container before the application starts.
#
# Configuration comes from the environment so the deployer -- not the
# image author -- controls the trust root:
#   MODELGUARD_TRUSTED_FINGERPRINT  required; sha256 of the trusted public key
#   MODELGUARD_MODEL_DIR            default /opt/model
#   MODELGUARD_BOM / _SIGNATURE / _POLICY   default /opt/modelguard/...
set -eu

if [ -z "${MODELGUARD_TRUSTED_FINGERPRINT:-}" ]; then
    echo "modelguard: MODELGUARD_TRUSTED_FINGERPRINT is not set; refusing to start." >&2
    exit 78
fi

model_dir="${MODELGUARD_MODEL_DIR:-/opt/model}"
bom="${MODELGUARD_BOM:-/opt/modelguard/model.bom.json}"
signature="${MODELGUARD_SIGNATURE:-/opt/modelguard/model.sig.json}"
policy="${MODELGUARD_POLICY:-/opt/modelguard/policy.yaml}"

if ! modelguard policy check "$model_dir" \
        --mbom "$bom" \
        --signature "$signature" \
        --policy "$policy" \
        --trusted-fingerprint "$MODELGUARD_TRUSTED_FINGERPRINT"; then
    echo "modelguard: model verification failed; refusing to start." >&2
    exit 78
fi

exec "$@"
