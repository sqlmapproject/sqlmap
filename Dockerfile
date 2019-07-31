FROM python:3.8.0b2-alpine3.10

LABEL version="1.3.7.42" \
      docker_build="docker build -t sqlmapproject/sqlmap:1.3.7.42 ." \
      docker_run="docker run --rm -ti sqlmapproject/sqlmap:1.3.7.42 --url http://www.example.com"

COPY [".", "/sqlmap"]

WORKDIR /sqlmap

ENTRYPOINT ["python", "sqlmap.py"]
