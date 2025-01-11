FROM rust:1.83.0-alpine AS builder
WORKDIR /usr/src/server
COPY . .

RUN apk add --no-cache musl-dev && \
    cargo build --release --color=always --package send

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/src/send/target/release/send /usr/local/bin/server

ENV RUST_LOG="info,sqlx=info,send=debug,backend=debug"
CMD ["send"]
EXPOSE 3000
