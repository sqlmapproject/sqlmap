FROM python:2-alpine

RUN apk add --update git
RUN pip install bs4

WORKDIR /root

RUN git clone https://github.com/sqlmapproject/sqlmap.git sqlmap

RUN chmod +x /root/sqlmap/sqlmap.py

RUN ln -s /root/sqlmap/sqlmap.py /usr/bin/sqlmap

ENTRYPOINT ["sqlmap"]

CMD ["-h"]


