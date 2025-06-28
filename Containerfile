FROM rust:latest as builder

WORKDIR /rust-backend
COPY . .

RUN cargo install --path .

FROM debian:latest
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/bqwebsite-backend /usr/local/bin/bqwebsite-backend
CMD ["bqwebsite-backend"]
EXPOSE 3000