# Build the server from the source in this repo (the old Dockerfile ran
# `go install ...@latest`, which ignored local changes and built upstream).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /airliftd ./cmd/airliftd

# Minimal, non-root runtime image. The app dir defaults to the nonroot user's
# ~/.airliftd; mount a volume there (or set AIRLIFT_HOME) to persist uploads.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /airliftd /usr/local/bin/airliftd
EXPOSE 60606
ENTRYPOINT ["/usr/local/bin/airliftd"]
