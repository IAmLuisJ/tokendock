# Pinned by digest, and kept in step with the go directive in go.mod: the
# official image sets GOTOOLCHAIN=local, so it will not fetch a newer
# toolchain than it ships with.
FROM golang:1.26.8@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tokendock ./cmd/tokendock

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /tokendock /tokendock
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=2s --start-period=2s --retries=15 \
  CMD ["/tokendock", "-healthcheck"]
ENTRYPOINT ["/tokendock"]
