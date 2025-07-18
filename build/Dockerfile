FROM public.ecr.aws/docker/library/rust:1.88.0

ARG TARGETARCH

# If not using buildx with --platform, TARGETARCH will be undefined and the build will fail.  Assume
# x86 as the default in that case.
ENV TARGETARCH=${TARGETARCH:-amd64}

WORKDIR /tmp

RUN set -eux; \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        docker.io \
        ca-certificates \
        build-essential \
        llvm \
        clang \
        libclang-dev \
        lld \
        cmake \
        libssl-dev \
        liblz4-dev \
        curl \
        protobuf-compiler \
        rsync && \
    rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml .

RUN rustup default "$(cat rust-toolchain.toml | grep channel | sed -e 's/.*"\(.*\)"/\1/')"; \
    rm rust-toolchain.toml
RUN rustup component add clippy rustfmt

RUN curl -L https://github.com/docker/compose/releases/download/v2.6.0/docker-compose-linux-`uname -m` \
      -o /usr/local/bin/docker-compose && \
    chmod a+x /usr/local/bin/docker-compose

RUN cargo install --locked \
      sccache \
      detect_flake \
      critcmp \
      cargo-deny
ENV RUSTC_WRAPPER=sccache

# Install cargo-nextest
RUN set -eux; \
    VERSION="0.9.87"; \
    case "${TARGETARCH}" in \
      "arm64") PLATFORM="linux-arm";; \
      "amd64") PLATFORM="linux";; \
      *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1;; \
    esac; \
    # CARGO_HOME is set by the nightly container to be /usr/local/cargo.
    # This is where it reads configs from for cargo and where cargo installs binaries.
    curl -LsSf "https://get.nexte.st/${VERSION}/${PLATFORM}" | tar zxf - -C ${CARGO_HOME}/bin

# Set some rustflags.  For info on the graviton flag, see:
#   https://github.com/aws/aws-graviton-getting-started/blob/main/rust.md
RUN linker_flag='"-C", "link-arg=-fuse-ld=lld"' \
    && graviton_flag='"-C", "target-feature=+lse"' \
    && if [ "${TARGETARCH}" = "arm64" ]; then \
         rustflags="${linker_flag}, ${graviton_flag}"; \
       else \
         rustflags="${linker_flag}"; \
       fi \
    && printf '[build]\nrustflags = [%s]\n' "${rustflags}" > ${CARGO_HOME}/config.toml
