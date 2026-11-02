# syntax=docker/dockerfile:1

# Build the overlay-hub server image.
#   docker build -t overlay-relay:0.1.0 .
# The image runs as a non-root user and reads its configuration from the environment.
# Required at run time: OVERLAY_ALLOWED_HOST (see server/README.md).

ARG RUST_IMAGE=docker.io/library/rust:1-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY server/ ./server/
RUN cargo build --release --locked --manifest-path server/Cargo.toml --bin overlay-hub \
 && install -D -m 0755 server/target/release/overlay-hub /out/usr/local/bin/overlay-hub \
 && install -d -m 0755 /out/etc/overlay-relay \
 && install -d -m 0700 -o 65532 -g 65532 /out/var/lib/overlay-relay

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/ /
ENV OVERLAY_PEERS_PATH=/etc/overlay-relay/peers.json \
    OVERLAY_DATA_DIR=/var/lib/overlay-relay \
    OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697
EXPOSE 6697
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/overlay-hub"]
