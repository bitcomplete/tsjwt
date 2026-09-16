# Build the daemon. The tsnetid module carries the Tailscale dependency; the
# core module stays stdlib-only, so a backend that only verifies tokens does
# not pull any of this in.
#
# The build stage pins to BUILDPLATFORM and cross-compiles to TARGETARCH.
# Running the Go toolchain under emulation instead is not viable: the
# compiler segfaults part-way through the Tailscale tree.
# 1.26 because the gateway module's Kubernetes dependencies require it. The
# core and tsnetid modules still build with 1.25.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETARCH
ARG TARGETOS=linux
WORKDIR /src
COPY go.mod go.work ./
COPY tsnetid/go.mod tsnetid/go.sum ./tsnetid/
COPY gateway/go.mod gateway/go.sum ./gateway/
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

# The Gateway API implementation. The controller decides routes; the data
# plane serves them. They are separate binaries because they have different
# jobs and very different blast radii: the controller can be down without
# stopping traffic, and the data plane must not need the API server.
RUN cd gateway && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags="-s -w" \
      -o /out/tsjwt-controller ./cmd/tsjwt-controller
RUN cd gateway && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags="-s -w" \
      -o /out/tsjwt-dataplane ./cmd/tsjwt-dataplane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tsjwtd /usr/local/bin/tsjwtd
COPY --from=build /out/tsjwt-echo /usr/local/bin/tsjwt-echo
COPY --from=build /out/tsjwt-controller /usr/local/bin/tsjwt-controller
COPY --from=build /out/tsjwt-dataplane /usr/local/bin/tsjwt-dataplane
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tsjwtd"]
