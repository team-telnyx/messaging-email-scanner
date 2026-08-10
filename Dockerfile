FROM rspamd/rspamd:3.10@sha256:4de95ab3c983e5b1ca1433e37a94dc0b7e804915d06fc2e5a47d086282833760

LABEL org.opencontainers.image.title="messaging-email-scanner"
LABEL org.opencontainers.image.description="Rspamd outbound content scanner for Telnyx Email"
LABEL org.opencontainers.image.source="https://github.com/team-telnyx/messaging-email-scanner"

# Base image runs as UID 11333 — switch to root for package install
USER root

# Rspamd base is Debian 12 (Bookworm). drill is in ldnsutils.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ldnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Rspamd configuration
COPY --chown=11333:11333 config/local.d/ /etc/rspamd/local.d/
COPY --chown=11333:11333 config/override.d/ /etc/rspamd/override.d/

# Copy maps
COPY --chown=11333:11333 config/local.d/maps.d/ /etc/rspamd/local.d/maps.d/

# Copy entrypoint and healthcheck scripts
COPY --chown=11333:11333 scripts/entrypoint.sh /entrypoint.sh
COPY --chown=11333:11333 scripts/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Switch back to Rspamd user
USER 11333:11333

# Health check uses perl (already in the base image)
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD sh /healthcheck.sh

# Expose scanner and controller ports
EXPOSE 11333 11334

# Start Rspamd with password injection
ENTRYPOINT ["/entrypoint.sh"]
