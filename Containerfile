# Stage 1: Build web assets
FROM registry.access.redhat.com/hi/nodejs:latest AS web-builder
USER root
RUN mkdir -p /build && chown 65532:0 /build
USER 65532
WORKDIR /build
COPY --chown=65532:0 web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY --chown=65532:0 web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM registry.access.redhat.com/hi/go:latest AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /build/dist/ web/dist/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -w -s" -o /lw ./cmd/lw

# Stage 3: Minimal runtime
FROM registry.access.redhat.com/hi/core-runtime:latest
COPY --from=go-builder /lw /lw
EXPOSE 8443
ENTRYPOINT ["/lw", "relay", "--self-signed"]
