FROM python:3.10
WORKDIR /app
COPY ./requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
RUN adduser worker

COPY ./static /app/static
COPY ./config.yaml /app/config.yaml
COPY ./config.py /app/config.py
COPY ./const.py /app/const.py
COPY ./logging_config.py /app/logging_config.py
COPY ./main.py /app/main.py
COPY ./runners.py /app/runners.py
COPY ./timer.py /app/timer.py
COPY ./utils.py /app/utils.py

RUN chown -R worker /app

EXPOSE 8000

USER worker

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--access-log"]
