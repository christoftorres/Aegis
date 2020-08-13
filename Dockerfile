FROM ubuntu:18.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update
RUN apt-get install -y sudo wget tar unzip pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common python3-pip iputils-ping

WORKDIR /root
COPY aegis aegis

# Install dependencies
RUN cd aegis && pip3 install -r requirements.txt
