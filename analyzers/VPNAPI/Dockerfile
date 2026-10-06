FROM python:3-slim
WORKDIR /worker
COPY . VPNAPI
# pip is only needed to build; Trivy flags the libraries it vendors.
RUN pip install --no-cache-dir -r VPNAPI/requirements.txt \
 && pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3*/ensurepip
ENTRYPOINT ["python3", "VPNAPI/vpnapi.py"]
