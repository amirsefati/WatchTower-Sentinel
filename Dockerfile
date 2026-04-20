FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/watchtower-sentinel ./cmd/watchtower-sentinel

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=build /out/watchtower-sentinel /usr/local/bin/watchtower-sentinel
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/watchtower-sentinel"]
