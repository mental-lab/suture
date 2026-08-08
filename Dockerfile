# Self-contained build on Wolfi/Chainguard images. Releases are built by
# GoReleaser (see .goreleaser.yaml and goreleaser.Dockerfile); this file is
# for building the tool from source directly:
#
#   docker build -t suture .
FROM cgr.dev/chainguard/go:latest-dev AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/suture .

FROM cgr.dev/chainguard/static:latest
COPY --from=build /out/suture /usr/local/bin/suture
ENTRYPOINT ["/usr/local/bin/suture"]
