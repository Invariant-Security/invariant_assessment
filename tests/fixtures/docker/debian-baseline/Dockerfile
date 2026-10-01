# Debian 11 -- clean baseline for the bxsec demo. Should PASS both
# assessed controls (5.1.20 sshd PermitRootLogin, 7.1.5 /etc/shadow perms).
FROM debian:11

# O LTS do Debian 11 terminou (ago/2026) e os pacotes saíram do espelho
# principal (apt-get dava 404 em bullseye-security). O archive.debian.org
# mantém o bullseye principal (o -security ainda não foi arquivado lá) --
# preserva a cobertura do documento debian_linux_11 em vez de trocar a
# fixture de versão. Fixture de teste: não precisa das atualizações de
# segurança.
RUN echo 'deb http://archive.debian.org/debian bullseye main' > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive

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

CMD ["sleep", "infinity"]
