# syntax=docker/dockerfile:1

# Build the overlay-hub server image.
#   docker build -t overlay-relay:local .
# The image runs as a non-root user and reads its
# configuration from the environment.
# Nothing is required at run time (see server/README.md).

ARG GO_IMAGE=docker.io/library/golang:1.26-trixie
ARG RUNTIME_IMAGE=docker.io/library/debian:13-slim

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum version.go ./
COPY client/ ./client/
COPY server/ ./server/
RUN GOWORK=off CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/overlay-hub ./server

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/overlay-hub /usr/local/bin/overlay-hub
RUN mkdir -p /var/lib/overlay-relay \
 && chown 65532:65532 /var/lib/overlay-relay \
 && chmod 0700 /var/lib/overlay-relay
ENV OVERLAY_DATA_DIR=/var/lib/overlay-relay \
    OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697
EXPOSE 6697
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/overlay-hub"]
