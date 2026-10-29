# INV-49 fixture: a host with sshd AND auditd, reached over real SSH as an
# unprivileged user (never root), so the assessment runs the way a customer
# host with a non-root login would. Separate from ssh-target on purpose (that
# one is the SSHTransport/host-key fixture). Debian's auditd package ships
# /etc/audit as 0750 root:root, which is the "directory unreadable behind a
# glob" case.
FROM debian:11

RUN echo 'deb http://archive.debian.org/debian bullseye main' > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server auditd \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
    && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Deliberately weak throwaway credentials; bound to 127.0.0.1 only (compose).
RUN useradd -m -s /bin/sh invariant-nonroot \
    && echo 'invariant-nonroot:invariant-nonroot-password' | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
