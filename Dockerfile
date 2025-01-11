FROM rust:1.83.0-alpine AS builder
WORKDIR /usr/src/server
COPY . .

RUN apk add --no-cache musl-dev && \
    cargo build --release --color=always --package server

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/src/server/target/release/server /usr/local/bin/server

ENV RUST_LOG="info,sqlx=info,server=debug"
CMD ["server"]
EXPOSE 3000
