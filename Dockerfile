FROM python:3.10
WORKDIR /app
COPY ./requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
RUN adduser worker

COPY ./static /app/static
COPY ./config.yaml /app/config.yaml
COPY ./main.py /app/main.py
COPY ./logging.conf /app/logging.conf

RUN chown -R worker /app

EXPOSE 8000

USER worker

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--access-log"]
