# Stage 1: Build all workspace crates
FROM docker.io/library/rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y libpam0g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --workspace --release

# Stage 2: Runtime image with SSSD proxy, NSS and PAM modules installed
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y \
        sssd sssd-proxy libpam-runtime libpam-modules pamtester curl \
    && rm -rf /var/lib/apt/lists/*

# Install NSS module (glibc looks for libnss_<name>.so.2)
COPY --from=builder /build/target/release/libnss_oidc.so \
     /usr/lib/x86_64-linux-gnu/libnss_oidc.so.2

# Install PAM module
COPY --from=builder /build/target/release/libpam_oidc.so \
     /usr/lib/x86_64-linux-gnu/security/pam_oidc.so

# Install mock-idp binary (used when running standalone tests)
COPY --from=builder /build/target/release/mock-idp /usr/local/bin/mock-idp

# Configure NSS to use our oidc module (after files)
RUN sed -i 's/^passwd:.*/passwd: files oidc/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:  files oidc/' /etc/nsswitch.conf

# PAM service config for "oidc"
RUN echo "auth required pam_oidc.so" > /etc/pam.d/oidc && \
    echo "account required pam_oidc.so" >> /etc/pam.d/oidc

# SSSD config
COPY test/sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf

# sssd-oidc config
RUN mkdir -p /etc/sssd-oidc
COPY test/config.toml /etc/sssd-oidc/config.toml

# Cache directory
RUN mkdir -p /var/lib/sssd-oidc

CMD ["/bin/sleep", "infinity"]
