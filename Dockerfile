FROM ubuntu:latest

RUN apt-get -y update --fix-missing
RUN apt-get install python3 pip -y

ENV TZ=Asia/Singapore
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get install -y \
        iputils-ping \
        python-setuptools \
        wget \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        zlib1g-dev \
        iptables \
        libnetfilter-queue-dev \
        tcpdump \
        unzip \
        vim \
        openssl \
        libssl-dev \
        libnghttp2-dev \
        libdnet \
        autoconf \
        libtool \
        libtool-bin \
        luajit \
        libluajit-5.1-dev

# Define Working Directory
WORKDIR /opt
ENV DAQ_VERSION 2.0.7
RUN wget --no-check-certificate https://www.snort.org/downloads/archive/snort/daq-${DAQ_VERSION}.tar.gz \
    && tar xvfz daq-${DAQ_VERSION}.tar.gz \
    && cd daq-${DAQ_VERSION} \
    && autoreconf -ivf \
    && ./configure; make; make install
    
ENV SNORT_VERSION 2.9.18.1
RUN wget --no-check-certificate https://www.snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz \
    && tar xvfz snort-${SNORT_VERSION}.tar.gz \
    && cd snort-${SNORT_VERSION} \
    && ./configure --enable-perfprofiling; make; make install
    
RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules
    
RUN ldconfig

# Copying source code foler
COPY . websnort
#RUN pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org  -r websnort/requirements.txt

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz
# # Create snort folder in /etc directory
# COPY ./snort /etc

# RUN chmod a+r /etc/snort/etc/snort.conf


# # RUN pip install websnort
# ENV PYTHONPATH "${PYTHONPATH}:/opt/websnort"
# RUN mkdir websnort
# COPY websnort/ websnort
# RUN pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r websnort/requirements.txt
# RUN mv websnort/websnort /usr/local/bin/

# CMD '/usr/local/bin/websnort'
        
        
