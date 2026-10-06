FROM python:3-slim
WORKDIR /worker
COPY . VPNAPI
RUN pip install --no-cache-dir -r VPNAPI/requirements.txt
ENTRYPOINT ["python3", "VPNAPI/vpnapi.py"]
