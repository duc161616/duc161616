# Static bbguard binary on a minimal base. No CGO, no shell needed at runtime.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY internal/ ./internal/
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bbguard ./cmd/bbguard

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/bbguard /bbguard
# Scope file and audit log are bind-mounted; see deploy/docker-compose.yml.
VOLUME ["/data"]
EXPOSE 8899
ENTRYPOINT ["/bbguard"]
CMD ["-scope", "/data/scope.json", "-addr", ":8899", "-audit", "/data/audit.jsonl"]
