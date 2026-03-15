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
        openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Detect multiarch lib directory (works on both x86_64 and aarch64)
RUN echo "/usr/lib/$(uname -m)-linux-gnu" > /tmp/libdir

# Install NSS module (glibc looks for libnss_<name>.so.2)
COPY --from=builder /build/target/release/libnss_oidc.so /tmp/libnss_oidc.so
RUN cp /tmp/libnss_oidc.so "$(cat /tmp/libdir)/libnss_oidc.so.2"

# Install PAM module
COPY --from=builder /build/target/release/libpam_oidc.so /tmp/libpam_oidc.so
RUN cp /tmp/libpam_oidc.so "$(cat /tmp/libdir)/security/pam_oidc.so"

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
RUN echo -n "test-bearer-token" > /etc/sssd-oidc/scim-token && \
    chmod 600 /etc/sssd-oidc/scim-token

# Cache directory
RUN mkdir -p /var/lib/sssd-oidc

# --- SSH setup for e2e testing ---
RUN mkdir -p /run/sshd && \
    ssh-keygen -A

# PAM config for sshd: use pam_oidc for account checks, permit auth
# (auth is handled by SSH public-key; PAM only does account management)
RUN echo "auth    sufficient pam_permit.so"  > /etc/pam.d/sshd && \
    echo "account required   pam_oidc.so"   >> /etc/pam.d/sshd && \
    echo "session required   pam_permit.so" >> /etc/pam.d/sshd

# Install test SSH key for alice
COPY test/ssh_test_key.pub /tmp/ssh_test_key.pub

# Entrypoint script that creates the OIDC user home and starts sshd
COPY test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/bin/sleep", "infinity"]
