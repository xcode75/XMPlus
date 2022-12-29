# Build go
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o XMPlus -trimpath -ldflags "-s -w -buildid=" ./main

FROM  alpine
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XMPlus/
COPY --from=builder /app/XMPlus /usr/local/bin

ENTRYPOINT [ "XMPlus", "--config", "/etc/XMPlus/config.yml"]