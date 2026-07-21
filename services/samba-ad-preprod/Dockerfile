FROM debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG SAMBA_DEBIAN_VERSION=2:4.22.10+dfsg-0+deb13u1

ENV DEBIAN_FRONTEND=noninteractive

COPY --chmod=0755 policy-rc.d /usr/sbin/policy-rc.d

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        python3-setproctitle \
        samba-ad-dc="${SAMBA_DEBIAN_VERSION}" \
        samba-ad-provision="${SAMBA_DEBIAN_VERSION}" \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/samba/smb.conf \
    && chmod 0755 /usr/sbin/policy-rc.d

COPY samba-ad-entrypoint /usr/local/sbin/samba-ad-entrypoint
COPY samba-ad-healthcheck /usr/local/sbin/samba-ad-healthcheck
COPY samba-ad-secret-tool /usr/local/sbin/samba-ad-secret-tool

RUN chmod 0755 \
        /usr/local/sbin/samba-ad-entrypoint \
        /usr/local/sbin/samba-ad-healthcheck \
        /usr/local/sbin/samba-ad-secret-tool \
    && mkdir -p \
        /etc/samba \
        /var/cache/samba \
        /var/lib/samba \
        /var/log/samba \
        /run/samba

HEALTHCHECK --interval=15s --timeout=8s --start-period=90s --retries=4 \
    CMD ["/usr/local/sbin/samba-ad-healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/sbin/samba-ad-entrypoint"]
CMD ["samba", "-i", "--debug-stdout", "--no-process-group"]
