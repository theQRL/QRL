#Download base ubuntu image
FROM ubuntu:16.04
RUN apt-get update
RUN apt-get -y install ca-certificates curl

# Prepare pip
RUN apt-get -y install python-pip
RUN pip install --upgrade pip
RUN pip install -i https://testpypi.python.org/pypi --extra-index-url https://pypi.python.org/simple/  --upgrade qrl

# ENV - Define environment variables
# TODO: define Required environment variables

# COPY - Copy configuration/scripts
COPY scripts/start.sh /root/start.sh

# VOLUME - link directories to host

# TODO: Map to host directory to keep wallets outside

# START SCRIPT
CMD ["/root/start.sh"]

# EXPOSE PORTS

# TODO: Map ports to get access from outside

