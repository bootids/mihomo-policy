FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mihomo-policy ./cmd/mihomo-policy

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 policy && adduser -D -u 10001 -G policy policy
WORKDIR /app
COPY --from=build /mihomo-policy /usr/local/bin/mihomo-policy
COPY --chown=policy:policy policy /app/policy
RUN mkdir -p /app/data /app/local && chown -R policy:policy /app/data /app/local
USER 10001:10001
ENTRYPOINT ["mihomo-policy"]
CMD ["serve", "--config", "/app/local/runtime.yaml"]
