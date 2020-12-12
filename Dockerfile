FROM golang:latest

RUN apt update && apt install -y \
    apache2 \
    vim \
    augeas-tools \
    libaugeas-dev
ARG a2confDir=/opt/a2conf
RUN mkdir $a2confDir
COPY . $a2confDir
WORKDIR  $a2confDir

CMD ["go", "test", "./..."]
