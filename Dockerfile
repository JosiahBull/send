FROM alpine:3.21
WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY ./target/tmp/server /app/server

ENV RUST_LOG="info,sqlx=info,server=debug"
CMD ["/app/server"]
EXPOSE 3000
