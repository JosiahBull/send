FROM rust:1.83.0-alpine AS chef
WORKDIR /usr/src/server
RUN apk add --no-cache musl-dev
RUN cargo install --locked cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /usr/src/server/recipe.json recipe.json
# Build dependencies - should be cached for faster rebuilds.
RUN cargo chef cook --recipe-path recipe.json

# Build the project
COPY . .
RUN cargo build --release --color=always --package server

FROM alpine:3.18 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/src/server/target/release/server /usr/local/bin/server

ENV RUST_LOG="info,sqlx=info,server=debug"
CMD ["server"]
EXPOSE 3000
