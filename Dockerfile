FROM python:3-slim

RUN pip install oscrypto
RUN pip install certbuilder
RUN pip install connexion
RUN pip install connexion[swagger-ui]

EXPOSE 8080

WORKDIR /usr/local/app

ENTRYPOINT [ "python", "./python/main.py" ]
