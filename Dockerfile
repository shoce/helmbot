
# https://hub.docker.com/_/golang/tags
FROM golang:1.23.2-alpine3.20 AS build
RUN mkdir -p /root/helmbot/
COPY helmbot.go go.mod /root/helmbot/
WORKDIR /root/helmbot/
RUN go version
RUN go get -a -v
RUN ls -l -a
RUN go build -o helmbot helmbot.go
RUN ls -l -a


# https://hub.docker.com/_/alpine/tags
FROM alpine:3.20.3
RUN apk add --no-cache gcompat && ln -s -f -v ld-linux-x86-64.so.2 /lib/libresolv.so.2
RUN mkdir -p /opt/zz/
RUN mkdir -p /opt/helmbot/
COPY --from=build /root/helmbot/helmbot /opt/helmbot/helmbot
RUN ls -l -a /opt/helmbot/
WORKDIR /opt/helmbot/
ENTRYPOINT ["./helmbot"]


