FROM rust:bookworm as builder

# install protobuf
RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-dev musl-tools

COPY . /usr/src/app/
WORKDIR /usr/src/app/bindings/grpc
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --target x86_64-unknown-linux-musl --release --bin identity-grpc

FROM gcr.io/distroless/static-debian11 as runner

# get binary
COPY --from=builder /usr/src/app/bindings/grpc/target/x86_64-unknown-linux-musl/release/identity-grpc /

# set run env
EXPOSE 50051

# run it
CMD ["/identity-grpc"]