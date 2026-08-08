FROM cgr.dev/chainguard/static:latest
COPY suture /usr/local/bin/suture
ENTRYPOINT ["/usr/local/bin/suture"]
