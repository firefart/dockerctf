FROM ubuntu:latest
LABEL maintainer="firefart <firefart@gmail.com>"

ARG GOLANG_VERSION="1.19"
ARG GOLANG_SHASUM="464b6b66591f6cf055bc5df90a9750bf5fbc9d038722bb84a9d56a2bea974be6"
ARG APKTOOL_VERSION="2.6.1"
ARG JAVA_VERSION="18"
ARG JADX_VERSION="1.4.3"
ARG CFR_VERSION="0.152"

ARG DEBIAN_FRONTEND="noninteractive"

ENV HISTSIZE=5000
ENV HISTFILESIZE=10000
# looks like docker does not set this variable
ENV USER=root

RUN echo "shopt -s histappend" >> /root/.bashrc

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
  apt-get full-upgrade -y && \
  apt-get install -y \
  # tools
  git curl wget netcat socat build-essential tmux vim htop linux-headers-virtual dnsutils software-properties-common apt-utils \
  jq strace ltrace net-tools gdb gdb-multiarch binwalk steghide testdisk foremost sqlite3 pev yara netmask exiftool bsdmainutils \
  chromium-browser zsh aircrack-ng imagemagick mkisofs tree \
  # binwalk
  lzop lhasa \
  # sasquatch
  build-essential liblzma-dev liblzo2-dev zlib1g-dev \
  # JohnTheRipper
  libssl-dev zlib1g-dev yasm pkg-config libgmp-dev libpcap-dev libbz2-dev nvidia-opencl-dev ocl-icd-opencl-dev opencl-headers pocl-opencl-icd \
  # scanning
  nmap masscan \
  # python stuff
  python2 python3 python3-wheel python3-venv python3-requests python3-virtualenv python3-bs4 python3-pip python3-pycryptodome \
  # wpscan dependencies
  ruby ruby-dev rubygems zlib1g-dev liblzma-dev \
  # wfuzz dependencies
  python3-chardet python3-pycurl python3-future \
  # volatility dependencies
  pcregrep libpcre++-dev python2-dev python3-dev python3-pefile python3-capstone \
  # angr deps
  python3-dev libffi-dev build-essential \
  && \
  # java (needs wget and software-properties-common from above)
  wget -nv -O- https://apt.corretto.aws/corretto.key | apt-key add - && \
  add-apt-repository 'deb https://apt.corretto.aws stable main' && \
  apt-get update && apt-get install -y java-${JAVA_VERSION}-amazon-corretto-jdk && \
  # remove unneeded packages
  apt-get -y autoremove

# Install PIP2 and packages (are not available on the repo)
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py && \
  python2 /tmp/get-pip.py && \
  rm -f /tmp/get-pip.py
RUN pip2 install wheel requests pycryptodome

# make sure we can use python to launch python3
RUN update-alternatives --install /usr/local/bin/python python /usr/bin/python3 1
RUN rm -f /usr/local/bin/pip && update-alternatives --install /usr/local/bin/pip pip /usr/bin/pip3 1

# nodejs
RUN curl -sL https://deb.nodesource.com/setup_current.x | bash - && \
  apt-get install -y nodejs

# wordlists
RUN mkdir /wordlists && \
  wget -nv -O /wordlists/rockyou.txt https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt && \
  wget -nv -O /wordlists/directory-list-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-small.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-small.txt && \
  wget -nv -O /wordlists/jhaddix-all.txt https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt

# SecLists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /wordlists/SecLists

RUN git clone --depth 1 https://github.com/FlameOfIgnis/Pwdb-Public.git /wordlists/Pwdb-Public

RUN git clone --depth 1 https://github.com/assetnote/commonspeak2-wordlists /wordlists/commonspeak2

# oh my tmux
ENV TERM=xterm-256color
RUN git clone --depth 1 https://github.com/gpakosz/.tmux.git /root/.tmux && \
  ln -s -f /root/.tmux/.tmux.conf /root/.tmux.conf && \
  cp /root/.tmux/.tmux.conf.local /root/

# dotfiles
RUN git clone --depth 1 https://github.com/firefart/dotfiles /opt/dotfiles && \
  cd /opt/dotfiles && \
  ./setup.sh

# install go
RUN url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz" && \
  wget -O go.tgz -nv "$url" && \
  echo "${GOLANG_SHASUM} *go.tgz" | sha256sum -c - && \
  tar -C /usr/local -xzf go.tgz && \
  rm go.tgz

# update PATH
ENV GOPATH="/root/go"
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"

# gobuster
RUN go install github.com/OJ/gobuster/v3@dev

# ffuf
RUN go install github.com/ffuf/ffuf@master

# wpscan
RUN echo "gem: --no-ri --no-rdoc" > /etc/gemrc
RUN gem install wpscan

# apktool
RUN wget -nv -O /usr/local/bin/apktool https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && \
  chmod +x /usr/local/bin/apktool && \
  wget -nv -O /usr/local/bin/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar

# jadx
RUN wget -nv -O /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip && \
  unzip -qq /tmp/jadx.zip -d /opt/jadx/ && \
  rm -f /tmp/jadx.zip

# CFR java decompiler
RUN wget -nv -O /opt/cfr.jar https://github.com/leibnitz27/cfr/releases/download/${CFR_VERSION}/cfr-${CFR_VERSION}.jar

# update PATH
ENV PATH="${PATH}:/opt/jadx/bin"

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# wfuzz
RUN git clone --depth 1 https://github.com/xmendez/wfuzz.git /opt/wfuzz

# volatility
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git /opt/volatility && \
  # the version from apt will not work
  pip3 install yara-python pycryptodome && \
  mkdir -p /opt/volatility/volatility/symbols/ && \
  wget -nv -O /opt/volatility/volatility/symbols/windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip && \
  wget -nv -O /opt/volatility/volatility/symbols/mac.zip https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip && \
  wget -nv -O /opt/volatility/volatility/symbols/linux.zip https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip

# volatility2
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility.git /opt/volatility2 && \
  pip2 install distorm3==3.4.4 pycrypto openpyxl Pillow yara-python && \
  ln -fs /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

# libc-database
RUN git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database

# gdb GEF
RUN wget -nv -O ~/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/master/gef.py && \
  echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# Python Stuff
RUN pip3 install oletools angr

# pw cracking
RUN git clone --depth 1 https://github.com/magnumripper/JohnTheRipper.git /opt/JohnTheRipper && \
  cd /opt/JohnTheRipper/src && \
  ./configure --disable-native-tests && \
  make -s clean && \
  make -sj4 && \
  make shell-completion

# OSINT Section

# ASNLookup
RUN git clone --depth 1 https://github.com/yassineaboukir/Asnlookup /opt/asnlookup && \
  pip3 install -r /opt/asnlookup/requirements.txt

# ASNRecon
RUN git clone --depth 1 https://github.com/orlyjamie/asnrecon /opt/asnrecon && \
  pip3 install -r /opt/asnrecon/requirements.txt

# Amass
RUN git clone --depth 1 https://github.com/OWASP/Amass.git /opt/amass && \
  cd /opt/amass && go get ./... && go install ./...

# DomLink
RUN git clone --depth 1 https://github.com/vysecurity/DomLink.git /opt/domlink && \
  pip3 install -r /opt/domlink/requirements.txt

# GoSpider
RUN go install github.com/jaeles-project/gospider@master

# Hakkawler
RUN go install github.com/hakluke/hakrawler@master

# Subdomainzier
RUN git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/subdomainizer && \
  pip3 install -r /opt/subdomainizer/requirements.txt

# Subfinder
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@master

# httprobe
RUN go install github.com/tomnomnom/httprobe@master

# nuclei
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@master

# aquatone
RUN go install github.com/firefart/aquatone@master

# brutespray
RUN git clone --depth 1 https://github.com/x90skysn3k/brutespray.git /opt/brutespray && \
  pip3 install -r /opt/brutespray/requirements.txt

# uncompyle
RUN git clone --depth 1 https://github.com/rocky/python-uncompyle6.git /opt/uncompyle6 && \
  cd /opt/uncompyle6 && \
  python3 setup.py install

# httpx
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@master

# sherlock
RUN git clone --depth 1 https://github.com/sherlock-project/sherlock /opt/sherlock && \
  cd /opt/sherlock && \
  python3 -m pip install -r requirements.txt

# sasquatch
RUN git clone --depth 1 https://github.com/devttys0/sasquatch.git /opt/sasquatch && \
  cd /opt/sasquatch && \
  wget https://patch-diff.githubusercontent.com/raw/devttys0/sasquatch/pull/47.patch -O 47.patch && \
  patch -p1 < 47.patch && \
  ./build.sh

# reset debian_frontend in the end
ENV DEBIAN_FRONTEND teletype

EXPOSE 80 443 8080 8443 9999 9090 1337

ENTRYPOINT [ "/bin/bash" ]
