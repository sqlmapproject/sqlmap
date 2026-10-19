FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.1.3 pymysql==1.2.3 'psycopg[binary]==3.3.6' python-tds==1.17.1 oracledb==26.0.1
WORKDIR /lab
COPY server.py db.py seed.py probe.py /lab/
CMD ["python", "/lab/server.py"]
