# The Gate 1 images (WEEK2_PLAN §4, B1). Build from the WSL-side clone with `docker compose build`.
#
# - The trusted components (pep, broker, operator) and the test-only agent and oracle are
#   static x86_64-unknown-linux-musl binaries on `scratch`: no shell, no libc, no package
#   manager. Each image gets a hand-built root: a real /run owned by root (bind_safe_listener
#   checks every ancestor of a socket), and its state directory with §4's owner and mode.
# - The tool servers build for glibc and run on the matching debian:bookworm-slim (B1).
# - broker-capture, injector and probe are test images, for compose/gate1.yaml. Their binaries
#   are built here with the rest, but no release image copies them (RV4 #20).
# - Base images are pinned by index digest (resolved 2026-11-05); BuildKit's built-in
#   Dockerfile frontend is used, with no `# syntax=` image pulled at build time.

FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build
# The image's toolchain is the pin (rust-toolchain.toml stays out of the context, so rustup
# does not fetch the macOS target or the lint components); only the musl target is added.
RUN rustup target add x86_64-unknown-linux-musl && rustc --version | grep -q '^rustc 1\.97\.1 '
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The target cache outlives this layer, and cargo trusts mtimes, which COPY preserves. So a source
# older than the cached build would ship the stale binary: found when a build of an altered tree
# left its PEP in the images built next from the real one. This layer only runs when the sources
# changed, so touching them rebuilds the crate then, and the dependencies stay cached.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find Cargo.toml Cargo.lock src -type f -exec touch {} + \
 && cargo build --release --locked --target x86_64-unknown-linux-musl \
        --bin pep-sidecar --bin stub-broker --bin stub-operator --bin stub-agent --bin stub-oracle \
        --bin stub-broker-capture --bin stub-injector \
 && cargo build --release --locked --bin stub-tool \
 && install -d /out \
 && for bin in pep-sidecar stub-broker stub-operator stub-agent stub-oracle stub-broker-capture stub-injector; do \
        install -m 0555 "target/x86_64-unknown-linux-musl/release/$bin" /out/; \
    done \
 && install -m 0555 target/release/stub-tool /out/

# The C-NET socket sweep (compose/probe/net-probe.c): static, so it runs on scratch. Its own stage
# so a change to it does not rebuild the crate.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS net-probe
COPY compose/probe/net-probe.c /src/net-probe.c
RUN install -d /out && gcc -static -O2 -Wall -Wextra -Werror -o /out/net-probe /src/net-probe.c

# The images' roots, with owners and modes, staged where `COPY --from` can take them whole.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS roots
RUN set -eu; \
    for image in pep broker operator agent oracle probe injector; do \
        install -d -m 0755 -o 0 -g 0 "/roots/$image/run" "/roots/$image/usr/local/bin" "/roots/$image/etc"; \
    done; \
    install -d -m 0700 -o 20002 -g 20002 /roots/pep/var/lib/pep; \
    install -d -m 2750 -o 20003 -g 20007 /roots/broker/var/lib/broker

FROM scratch AS pep
COPY --from=roots /roots/pep/ /
COPY --from=build /out/pep-sidecar /usr/local/bin/pep-sidecar
USER 20002:20002
ENTRYPOINT ["/usr/local/bin/pep-sidecar", "/etc/pep/config.json"]

FROM scratch AS broker
COPY --from=roots /roots/broker/ /
COPY --from=build /out/stub-broker /usr/local/bin/stub-broker
USER 20003:20003
ENTRYPOINT ["/usr/local/bin/stub-broker", "/etc/broker/config.json"]

FROM scratch AS operator
COPY --from=roots /roots/operator/ /
COPY --from=build /out/stub-operator /usr/local/bin/stub-operator
USER 20004:20004
ENTRYPOINT ["/usr/local/bin/stub-operator", "/run/pep-ctl/ctl.sock"]

FROM scratch AS agent
COPY --from=roots /roots/agent/ /
COPY --from=build /out/stub-agent /usr/local/bin/stub-agent
USER 20001:20001
ENTRYPOINT ["/usr/local/bin/stub-agent", "/run/pep/agent.sock"]

FROM scratch AS oracle
COPY --from=roots /roots/oracle/ /
COPY --from=build /out/stub-oracle /usr/local/bin/stub-oracle
USER 20006:20007
ENTRYPOINT ["/usr/local/bin/stub-oracle"]

# Test images: compose/gate1.yaml only.
FROM scratch AS broker-capture
COPY --from=roots /roots/broker/ /
COPY --from=build /out/stub-broker /usr/local/bin/stub-broker
COPY --from=build /out/stub-broker-capture /usr/local/bin/stub-broker-capture
USER 20003:20003
ENTRYPOINT ["/usr/local/bin/stub-broker-capture", "/var/lib/broker/proofs.jsonl", "/etc/broker/config.json"]

FROM scratch AS probe
COPY --from=roots /roots/probe/ /
COPY --from=build /out/stub-agent /usr/local/bin/stub-agent
COPY --from=net-probe /out/net-probe /usr/local/bin/net-probe
USER 20009:20001
ENTRYPOINT ["/usr/local/bin/stub-agent", "/run/pep/agent.sock"]

FROM scratch AS injector
COPY --from=roots /roots/injector/ /
COPY --from=build /out/stub-injector /usr/local/bin/stub-injector
USER 20002:20002
ENTRYPOINT ["/usr/local/bin/stub-injector", "/run/broker/broker.sock", "20003", "20003", "/var/lib/broker/proofs.jsonl"]

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS tool
ARG TOOL_UID
RUN install -d -m 2750 -o "${TOOL_UID:?}" -g 20007 /var/lib/tool
COPY --from=build /out/stub-tool /usr/local/bin/stub-tool
USER ${TOOL_UID}:${TOOL_UID}
ENTRYPOINT ["/usr/local/bin/stub-tool", "/etc/tool/config.json"]
