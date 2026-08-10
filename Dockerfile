FROM rspamd/rspamd:3.10@sha256:4de95ab3c983e5b1ca1433e37a94dc0b7e804915d06fc2e5a47d086282833760

LABEL org.opencontainers.image.title="messaging-email-scanner"
LABEL org.opencontainers.image.description="Rspamd outbound content scanner for Telnyx Email"
LABEL org.opencontainers.image.source="https://github.com/team-telnyx/messaging-email-scanner"

# Install required packages
RUN apk add --no-cache unbound drill

# Copy Rspamd configuration
COPY config/local.d/ /etc/rspamd/local.d/
COPY config/override.d/ /etc/rspamd/override.d/

# Copy maps
COPY config/local.d/maps.d/ /etc/rspamd/local.d/maps.d/

# Copy healthcheck script
COPY scripts/healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh

# Health check uses perl (already in the base image)
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD sh /healthcheck.sh

# Expose scanner and controller ports
EXPOSE 11333 11334

# Start Rspamd
CMD ["rspamd", "-f", "--var=RSPAMD_LOGGING_LEVEL=info"]
