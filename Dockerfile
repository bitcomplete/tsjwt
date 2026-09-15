# Build the daemon. The tsnetid module carries the Tailscale dependency; the
# core module stays stdlib-only, so a backend that only verifies tokens does
# not pull any of this in.
#
# The build stage pins to BUILDPLATFORM and cross-compiles to TARGETARCH.
# Running the Go toolchain under emulation instead is not viable: the
# compiler segfaults part-way through the Tailscale tree.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
ARG TARGETOS=linux
WORKDIR /src
COPY go.mod go.work ./
COPY tsnetid/go.mod tsnetid/go.sum ./tsnetid/
RUN go mod download all
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags="-s -w" \
      -o /out/tsjwtd ./tsnetid/cmd/tsjwtd
# The reference backend builds from the core module, so it carries no
# Tailscale code at all. That is the point of it: it is what an adopting
# service looks like.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags="-s -w" \
      -o /out/tsjwt-echo ./cmd/tsjwt-echo

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tsjwtd /usr/local/bin/tsjwtd
COPY --from=build /out/tsjwt-echo /usr/local/bin/tsjwt-echo
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tsjwtd"]
