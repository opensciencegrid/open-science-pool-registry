ARG BASE_OSG_SERIES=25
ARG BASE_OS=el9
ARG BASE_YUM_REPO=release

FROM opensciencegrid/software-base:$BASE_OSG_SERIES-$BASE_OS-$BASE_YUM_REPO

LABEL maintainer OSG Software <help@osg-htc.org>

# FIXME: this can be removed when we migrate to HTCSS 25 as the static
# setting is provided by upstream in the RPM
# SOFTWARE-6355: Ensure that the 'condor' UID/GID matches across containers
RUN groupadd -g 64 -r condor && \
    useradd -r -g condor -d /var/lib/condor -s /sbin/nologin \
      -u 64 -c "Owner of HTCondor Daemons" condor

RUN \
    yum update -y && \
    yum install -y condor && \
    yum install -y python3-pip httpd mod_auth_openidc mod_ssl python3-mod_wsgi && \
    yum clean all && rm -rf /var/cache/yum/*

COPY registry run_local.sh requirements.txt /opt/registry/
RUN pip3 install -U pip && pip3 install -r /opt/registry/requirements.txt

COPY register.py /usr/bin
COPY supervisor-apache.conf /etc/supervisord.d/40-apache.conf
COPY examples/apache.conf /etc/httpd/conf.d/
COPY examples/config.py wsgi.py registry /srv/
COPY registry /srv/registry/

ENV PYTHONUNBUFFERED=1
ENV CONFIG_DIR=/srv
ENV NO_CHOWN=1
#ENTRYPOINT ["/opt/registry/run_local.sh"]
#CMD ["--host=0.0.0.0"]
