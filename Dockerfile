FROM --platform=linux/amd64 golang:1.21-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o galactic-exchange main.go

FROM --platform=linux/amd64 alpine:latest
WORKDIR /root/
COPY --from=builder /app/galactic-exchange .
EXPOSE 8080
CMD ["./galactic-exchange"]