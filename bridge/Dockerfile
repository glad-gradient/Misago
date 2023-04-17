FROM python:3.10

RUN pip3 install --upgrade pip
COPY /bridge/requirements.txt /app/
RUN pip3 install -r /app/requirements.txt

COPY postgredb.env /app/
COPY /bridge/main.py /app/

COPY /bridge/configs.json /app/
COPY /bridge/forum_comments_creds.json /app/
COPY /bridge/forum_threads_creds.json /app/
COPY /bridge/ip_addresses.json /app/
COPY /bridge/user_agents.json /app/

COPY /bridge/db_manager.py /app/
COPY /bridge/detector.py /app/
COPY /bridge/utils.py /app/
WORKDIR /app/

CMD ["python3", "main.py"]
