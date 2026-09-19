# syntax=docker/dockerfile:1
#
# Example: verify a model at image BUILD time and again at container START.
# Not built or run in this repository's CI -- test it in your environment.
#
# Build context must contain: model/  model.bom.json  model.sig.json  policy.yaml
# entrypoint.sh (copy it from examples/docker/)
#
#   docker build \
#     --build-arg MODELGUARD_REF=<reviewed commit sha> \
#     --build-arg TRUSTED_FINGERPRINT=$(modelguard fingerprint publisher.modelguard.pub) \
#     --build-arg MODEL_ID=$(jq -r .payload.model_id model.sig.json) \
#     --build-arg MODEL_DIGEST=$(jq -r .payload.artifact_digest model.sig.json) \
#     --build-arg MBOM_DIGEST=$(jq -r .payload.mbom_digest model.sig.json) \
#     -t my-model:1.0.0 .
#
#   docker run --read-only -e MODELGUARD_TRUSTED_FINGERPRINT=<sha256> my-model:1.0.0

ARG MODELGUARD_REF

# ---- Stage 1: build-time gate ------------------------------------------
# BuildKit only builds stages the final image depends on. The final stage
# COPYs the model *from this stage*, so a failed check fails the build.
FROM python:3.12-slim AS verify
ARG MODELGUARD_REF
ARG TRUSTED_FINGERPRINT
RUN test -n "$MODELGUARD_REF" && test -n "$TRUSTED_FINGERPRINT"
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "git+https://github.com/sakthivarshans/modelguard.git@${MODELGUARD_REF}"
COPY model/ /opt/model/
COPY model.bom.json /opt/modelguard/model.bom.json
COPY model.sig.json /opt/modelguard/model.sig.json
COPY policy.yaml /opt/modelguard/policy.yaml
RUN modelguard policy check /opt/model \
      --mbom /opt/modelguard/model.bom.json \
      --signature /opt/modelguard/model.sig.json \
      --policy /opt/modelguard/policy.yaml \
      --trusted-fingerprint "$TRUSTED_FINGERPRINT"

# ---- Stage 2: runtime image ---------------------------------------------
FROM python:3.12-slim
ARG MODELGUARD_REF
ARG MODEL_ID
ARG MODEL_DIGEST
ARG MBOM_DIGEST

# These labels are INFORMATIONAL CLAIMS made by whoever built the image.
# Anyone can write any label, so never make a security decision from them.
# There is deliberately no org.modelguard.verification.status label: a
# build-time "verified" flag would be an unauthenticated assertion. The
# control is the startup check in entrypoint.sh, not a label.
LABEL org.modelguard.model.id="${MODEL_ID}" \
      org.modelguard.model.digest="${MODEL_DIGEST}" \
      org.modelguard.mbom.digest="${MBOM_DIGEST}"

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir "git+https://github.com/sakthivarshans/modelguard.git@${MODELGUARD_REF}" \
    && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY --from=verify /opt/model /opt/model
COPY --from=verify /opt/modelguard /opt/modelguard
COPY entrypoint.sh /usr/local/bin/modelguard-entrypoint
RUN chmod 0555 /usr/local/bin/modelguard-entrypoint \
    && useradd --system --no-create-home app \
    && chown -R root:root /opt/model /opt/modelguard \
    && chmod -R a-w /opt/model /opt/modelguard
USER app

ENTRYPOINT ["/usr/local/bin/modelguard-entrypoint"]
CMD ["python", "-c", "print('replace with your model server command')"]
