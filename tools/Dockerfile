FROM registry.fedoraproject.org/fedora:44
RUN dnf -y install createrepo_c rpm rpm-build rpm-sign gnupg2 python3 gh git tar gzip curl dnf5-plugins && dnf clean all
WORKDIR /source
ENV PYTHONDONTWRITEBYTECODE=1
