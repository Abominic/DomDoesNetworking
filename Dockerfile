FROM rust:1.58

COPY ./ ./

RUN cargo build --release

CMD ["/bin/bash -c ./target/release/project"]