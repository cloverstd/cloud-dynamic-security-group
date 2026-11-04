FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /cdsg ./cmd/cdsg

FROM --platform=$BUILDPLATFORM alpine:3.23 AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /cdsg /cdsg
USER 65532:65532
ENTRYPOINT ["/cdsg"]
CMD ["run", "--config", "/config/config.yaml"]
