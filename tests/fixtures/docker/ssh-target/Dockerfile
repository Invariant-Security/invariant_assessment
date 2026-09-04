# Debian 11, same base/sshd hardening as debian-baseline -- but unlike
# every other fixture here (only ever reached via `docker exec`, sshd
# never actually started as a daemon), this one exists specifically to
# be reached over a *real* SSH connection by SSHTransport (see
# tests/test_transport.py), so it needs sshd actually running in the
# foreground, a real login-capable test user, and password auth enabled.
FROM debian:11

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

RUN echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
    && echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config \
    && echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config \
    && echo "LoginGraceTime 30" >> /etc/ssh/sshd_config \
    && chmod 640 /etc/shadow \
    && chown root:shadow /etc/shadow

# Password auth enabled for THIS image only -- test_transport.py needs it
# for the password-auth test case. The other 6 baseline images are
# untouched and never get this directive.
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Test user SSHTransport authenticates as -- password is a deliberately
# weak, well-known, throwaway value that only ever works against this one
# disposable fixture container, bound to 127.0.0.1 only (see
# tests/fixtures/docker-compose.yml). Never used for anything real. Login
# shell is /bin/sh (not bash's usual useradd default) so an SSH
# exec_command call -- which runs a command through the account's own
# login shell -- produces the same shell (`sh`, not `bash`) that
# DockerExecTransport's `docker exec ... sh -c` always uses; without this
# the two transports' error-message wording for a missing binary differs
# cosmetically ("sh: 1: X: not found" vs "bash: line 1: X: command not
# found") for reasons that are about the shell, not the transport.
RUN useradd -m -s /bin/sh invariant-test \
    && echo 'invariant-test:invariant-test-password' | chpasswd

# .ssh dir prepared for later key injection (test_ssh_transport_key_auth
# appends an ephemeral pubkey to authorized_keys at runtime via `docker
# exec`) -- no key material baked into the image itself.
RUN mkdir -p /home/invariant-test/.ssh \
    && chown invariant-test:invariant-test /home/invariant-test/.ssh \
    && chmod 700 /home/invariant-test/.ssh

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
