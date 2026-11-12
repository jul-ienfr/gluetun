ARG GO_VERSION=1.26
ARG GO_ALPINE_VERSION=3.23
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine${GO_ALPINE_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY tests/integration/harness ./tests/integration/harness
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/harness ./tests/integration/harness

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache ca-certificates iproute2
COPY --from=build /out/harness /usr/local/bin/harness
ENTRYPOINT ["harness"]
