FROM python:3-slim
WORKDIR /worker
COPY . ProxyCheck
RUN pip install --no-cache-dir -r ProxyCheck/requirements.txt
ENTRYPOINT ["python3", "ProxyCheck/proxycheck.py"]
