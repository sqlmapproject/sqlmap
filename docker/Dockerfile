FROM ubuntu:20.04
RUN \
  # configure the "sqlmap" user
  groupadd sqlmap && \
  useradd sqlmap -s /bin/bash -m -g sqlmap -G sudo && \
  echo 'sqlmap:sqlmap' |chpasswd && \
  export DEBIAN_FRONTEND=noninteractive && \
  export TZ=Europe\Paris && \
  ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
  apt-get update && \
  # install utilities
  apt-get install -y \
    git \
    python3 \
    sudo && \
  # cleanup
  apt-get clean && \
  rm -rf \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

RUN ln -s /usr/bin/python3 /usr/bin/python

WORKDIR "/home/sqlmap/"

RUN \
  # install the sqlmap
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap && \
  # fix sqlmap user permissions
  chown -R sqlmap:sqlmap \
    /home/sqlmap/sqlmap && \
  # cleanup
  rm -rf \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

USER sqlmap
ENV PATH $PATH:/usr/bin
WORKDIR "/home/sqlmap/sqlmap"
CMD ["python", "sqlmap.py", "-hh"]