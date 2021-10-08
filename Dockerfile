FROM rust

WORKDIR /usr/src/lucky-commit
COPY . .

RUN cargo build --release --no-default-features

ENTRYPOINT ["/usr/src/lucky-commit/target/release/lucky_commit"]
