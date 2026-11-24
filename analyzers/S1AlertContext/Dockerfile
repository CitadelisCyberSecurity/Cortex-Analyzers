FROM python:3-slim
WORKDIR /worker
COPY . S1AlertContext
# The base image lags Debian security fixes, so upgrade OS packages.
# pip is only needed to build; Trivy flags the libraries it vendors.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir -r S1AlertContext/requirements.txt \
 && pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3*/ensurepip
ENTRYPOINT ["python3", "S1AlertContext/s1alertcontext.py"]
