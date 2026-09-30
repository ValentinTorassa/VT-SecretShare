# Build (works the same under `docker build` and `podman build`).
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/vt-secretshare .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/vt-secretshare /vt-secretshare
EXPOSE 8080
# Inside the container's own network namespace the app must listen on every
# interface for port publishing to reach it; restrict exposure where the port
# is published (docker-compose.yml binds it to 127.0.0.1 on the host).
ENV BIND_ADDR=0.0.0.0
USER nonroot:nonroot
ENTRYPOINT ["/vt-secretshare"]
