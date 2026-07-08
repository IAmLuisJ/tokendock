FROM golang:1.26 AS build
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
