# Build (works the same under `docker build` and `podman build` on valenpi).
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/vt-secretshare .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/vt-secretshare /vt-secretshare
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vt-secretshare"]
