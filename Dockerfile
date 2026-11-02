# syntax=docker/dockerfile:1

# Build the overlay-hub server image.
#   docker build -t overlay-relay:0.1.1 .
# The binary is linked statically against musl, so it does not depend on the
# runtime's C library. The image runs as a non-root user and reads its
# configuration from the environment.
# Required at run time: OVERLAY_ALLOWED_HOST (see server/README.md).

ARG RUST_IMAGE=docker.io/library/rust:1-slim
ARG RUNTIME_IMAGE=docker.io/library/debian:13-slim
ARG TARGET=x86_64-unknown-linux-musl

FROM ${RUST_IMAGE} AS build
ARG TARGET
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add "$TARGET"
WORKDIR /src
COPY server/ ./server/
RUN cargo build --release --locked --target "$TARGET" --manifest-path server/Cargo.toml --bin overlay-hub \
 && install -D -m 0755 server/target/"$TARGET"/release/overlay-hub /out/overlay-hub

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/overlay-hub /usr/local/bin/overlay-hub
RUN mkdir -p /etc/overlay-relay /var/lib/overlay-relay \
 && chown 65532:65532 /var/lib/overlay-relay \
 && chmod 0700 /var/lib/overlay-relay
ENV OVERLAY_PEERS_PATH=/etc/overlay-relay/peers.json \
    OVERLAY_DATA_DIR=/var/lib/overlay-relay \
    OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697
EXPOSE 6697
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/overlay-hub"]
