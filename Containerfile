FROM rust:latest as builder

WORKDIR /rust-backend
COPY . .

RUN cargo install --path .

FROM debian:latest
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/bqwebsite-backend /usr/local/bin/bqwebsite-backend
CMD ["bqwebsite-backend"]
EXPOSE 3000