FROM golang:latest

RUN apt update && apt install -y \
    apache2 \
    vim \
    augeas-tools \
    libaugeas-dev

ARG a2confDir=/opt/a2conf
ARG apacheAvailableSitesDir=/etc/apache2/sites-available

RUN mkdir $a2confDir
COPY . $a2confDir
WORKDIR  $a2confDir

COPY ./test_data/apache/example2.com.conf ${apacheAvailableSitesDir}
RUN a2ensite example2.com.conf && a2dissite 000-default.conf

CMD ["/bin/sh", "-c", "./test.sh"]
