FROM golang:latest

RUN apt update && apt install -y \
    apache2 \
    vim \
    augeas-tools \
    libaugeas-dev
RUN a2enmod ssl

ARG a2confDir=/opt/a2conf
ARG apacheAvailableSitesDir=/etc/apache2/sites-available

RUN mkdir $a2confDir
VOLUME ${a2confDir}
WORKDIR  $a2confDir

COPY ./test_data/apache/example2.com.conf ${apacheAvailableSitesDir}
COPY ./test_data/apache/example-ssl.com.conf ${apacheAvailableSitesDir}
COPY ./test_data/apache/example3.com.conf ${apacheAvailableSitesDir}
COPY ./test_data/apache/example3-ssl.com.conf ${apacheAvailableSitesDir}
RUN a2ensite example3.com.conf && a2ensite example3-ssl.com.conf && a2ensite example2.com.conf && a2ensite example-ssl.com.conf && a2dissite 000-default.conf

ENTRYPOINT ["/bin/sh", "./testcmd.sh"]
