FROM golang:1.23-alpine3.20 AS build
WORKDIR /go/src/github.com/calebdoxsey/tls13exampleserver
COPY go.mod main.go tls.go ./
RUN go build -o /usr/bin/tls13exampleserver

FROM alpine:3.20
COPY --from=build /usr/bin/tls13exampleserver /usr/bin/tls13exampleserver
EXPOSE 8443
ENTRYPOINT [ "/usr/bin/tls13exampleserver" ]
