# Build the daemon. The tsnetid module carries the Tailscale dependency; the
# core module stays stdlib-only, so a backend that only verifies tokens does
# not pull any of this in.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.work ./
COPY tsnetid/go.mod tsnetid/go.sum ./tsnetid/
RUN go mod download all
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/tsjwtd ./tsnetid/cmd/tsjwtd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tsjwtd /usr/local/bin/tsjwtd
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tsjwtd"]
