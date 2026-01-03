FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/main.py

# будем слушать unix socket через uvicorn
CMD ["uvicorn", "main:app", "--uds", "/run/wgctl/wgctl.sock", "--proxy-headers"]