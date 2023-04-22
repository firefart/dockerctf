FROM ubuntu:rolling
LABEL maintainer="firefart <firefart@gmail.com>"

# https://go.dev/dl/
ARG GOLANG_VERSION="1.20.3"
ARG GOLANG_SHASUM="979694c2c25c735755bf26f4f45e19e64e4811d661dd07b8c010f7a8e18adfca"
# https://aws.amazon.com/corretto/
ARG JAVA_VERSION="20"

# https://github.com/iBotPeaches/Apktool/releases/latest
ARG APKTOOL_VERSION="2.7.0"
# https://github.com/skylot/jadx/releases/latest
ARG JADX_VERSION="1.4.6"
# https://github.com/leibnitz27/cfr/releases/latest
ARG CFR_VERSION="0.152"
# https://github.com/pxb1988/dex2jar/releases/latest
ARG DEX2JAR_VERSION="2.1"
# https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu
ARG DOTNET_VERSION="6.0"
# https://portswigger.net/burp/releases/community/latest
ARG BURP_VERSION="2023.3.4"

ENV HISTSIZE=5000
ENV HISTFILESIZE=10000
# looks like docker does not set this variable
ENV USER=root
ENV DEBIAN_FRONTEND noninteractive
# disable .NET telemetry
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

RUN echo "shopt -s histappend" >> /root/.bashrc

RUN apt-get update && \
  apt-get full-upgrade -y && \
  apt-get install -y \
  # tools
  git curl wget netcat-traditional socat build-essential tmux vim htop linux-headers-virtual dnsutils \
  software-properties-common apt-utils jq strace ltrace net-tools gdb gdb-multiarch binwalk steghide \
  testdisk foremost sqlite3 pev yara netmask exiftool bsdmainutils unzip zsh aircrack-ng \
  imagemagick mkisofs tree openvpn wireguard php crunch hydra \
  # binwalk
  lzop lhasa \
  # sasquatch
  build-essential liblzma-dev liblzo2-dev zlib1g-dev \
  # JohnTheRipper
  libssl-dev zlib1g-dev yasm pkg-config libgmp-dev libpcap-dev libbz2-dev nvidia-opencl-dev \
  ocl-icd-opencl-dev opencl-headers pocl-opencl-icd \
  # scanning
  nmap masscan \
  # python stuff
  python3 python3-wheel python3-venv python3-requests python3-virtualenv \
  python3-bs4 python3-pip python3-pycryptodome \
  # python2
  libexpat1-dev libbz2-dev libreadline-dev libsqlite3-dev llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev \
  # wpscan dependencies
  ruby ruby-dev rubygems zlib1g-dev liblzma-dev \
  # wfuzz dependencies
  python3-chardet python3-pycurl python3-future \
  # volatility dependencies
  pcregrep libpcre2-dev python3-dev python3-pefile python3-capstone \
  # angr deps
  python3-dev libffi-dev build-essential \
  # arti deps
  sqlite3 libsqlite3-dev libssl-dev \
  # RsaCtfTool deps
  libmpfr-dev libmpc-dev \
  # android stuff
  android-sdk \
  # .NET SDK
  dotnet-sdk-${DOTNET_VERSION} \
  # google-chrome deps
  fonts-liberation libu2f-udev libvulkan1 xdg-utils \
  && \
  # java (needs wget and software-properties-common from above)
  wget -nv -O- https://apt.corretto.aws/corretto.key | apt-key add - && \
  add-apt-repository 'deb https://apt.corretto.aws stable main' && \
  apt-get update && apt-get install -y java-${JAVA_VERSION}-amazon-corretto-jdk && \
  # remove unneeded packages
  apt-get -y autoremove && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/*

# google chrome as chromium needs snap to install
RUN wget -O /tmp/google-chrome-stable_current_amd64.deb -nv "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" && \
  apt-get install -y /tmp/google-chrome-stable_current_amd64.deb && \
  rm -f /tmp/google-chrome-stable_current_amd64.deb

# python2
RUN wget -O /tmp/python2.tar.xz -nv https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tar.xz && \
  tar --extract --directory /usr/src/python2 --strip-components=1 --file /tmp/python2.tar.xz && \
  rm -f /tmp/python2.tar.xz && \
  cd /usr/src/python && \
  ./configure --enable-optimizations --enable-option-checking=fatal --with-ensurepip=install --enable-shared --with-lto --with-system-expat && \
  make -s -j "$(nproc)" && \
  make altinstall && \
  make clean

# rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

# arti: tor support
# rustscan: portscanner
RUN cargo install arti rustscan

# ferozbuster
RUN wget -nv -O /tmp/x86_64-linux-feroxbuster.zip https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip && \
  unzip -o /tmp/x86_64-linux-feroxbuster.zip -d /usr/bin && \
  chmod +x /usr/bin/feroxbuster && \
  rm -f /tmp/x86_64-linux-feroxbuster.zip

# Install python2 packages (are not available on the repo)
RUN pip2 install wheel requests pycryptodome

# make sure we can use python to launch python3
RUN update-alternatives --install /usr/local/bin/python python /usr/bin/python3 1
RUN rm -f /usr/local/bin/pip && update-alternatives --install /usr/local/bin/pip pip /usr/bin/pip3 1

# nodejs
RUN curl -sL https://deb.nodesource.com/setup_current.x | bash - && \
  apt-get update && \
  apt-get install -y nodejs && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/*

# wordlists
RUN mkdir /wordlists && \
  wget -nv -O /wordlists/rockyou.txt https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt && \
  wget -nv -O /wordlists/directory-list-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-small.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-small.txt && \
  wget -nv -O /wordlists/jhaddix-all.txt https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt && \
  wget -nv -O /wordlists/fuzz.txt https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt

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
RUN go install github.com/ffuf/ffuf@latest

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

# dex2jar
RUN wget -nv -O /tmp/dex2jar.zip  https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex2jar-${DEX2JAR_VERSION}.zip && \
  unzip -qq /tmp/dex2jar.zip -d /opt/dex2jar/ && \
  rm -f /tmp/dex2jar.zip

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# wfuzz
RUN git clone --depth 1 https://github.com/xmendez/wfuzz.git /opt/wfuzz

# volatility
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git /opt/volatility && \
  # the version from apt will not work
  python3 -m pip install yara-python pycryptodome && \
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
RUN python3 -m pip install oletools angr frida-tools objection

# pw cracking
RUN git clone --depth 1 https://github.com/magnumripper/JohnTheRipper.git /opt/JohnTheRipper && \
  cd /opt/JohnTheRipper/src && \
  ./configure --disable-native-tests && \
  make -s clean && \
  make -s -j "$(nproc)" && \
  make shell-completion

# OSINT Section

# ASNLookup
RUN git clone --depth 1 https://github.com/yassineaboukir/Asnlookup /opt/asnlookup && \
  python3 -m pip install -r /opt/asnlookup/requirements.txt

# ASNRecon
RUN git clone --depth 1 https://github.com/orlyjamie/asnrecon /opt/asnrecon && \
  python3 -m pip install -r /opt/asnrecon/requirements.txt

# Amass
RUN git clone --depth 1 https://github.com/OWASP/Amass.git /opt/amass && \
  cd /opt/amass && go get ./... && go install ./...

# DomLink
RUN git clone --depth 1 https://github.com/vysecurity/DomLink.git /opt/domlink && \
  python3 -m pip install -r /opt/domlink/requirements.txt

# GoSpider
RUN go install github.com/jaeles-project/gospider@latest

# Hakkawler
RUN go install github.com/hakluke/hakrawler@latest

# Subdomainzier
RUN git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/subdomainizer && \
  python3 -m pip install -r /opt/subdomainizer/requirements.txt

# Subfinder
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httprobe
RUN go install github.com/tomnomnom/httprobe@latest

# nuclei
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# aquatone
RUN go install github.com/firefart/aquatone@latest

# brutespray
RUN git clone --depth 1 https://github.com/x90skysn3k/brutespray.git /opt/brutespray && \
  python3 -m pip install -r /opt/brutespray/requirements.txt

# uncompyle
RUN git clone --depth 1 https://github.com/rocky/python-uncompyle6.git /opt/uncompyle6 && \
  cd /opt/uncompyle6 && \
  python3 setup.py install

# httpx
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# sherlock
RUN git clone --depth 1 https://github.com/sherlock-project/sherlock /opt/sherlock && \
  cd /opt/sherlock && \
  python3 -m pip install -r requirements.txt

# holehe
RUN git clone --depth 1 https://github.com/megadose/holehe.git /opt/holehe && \
  cd /opt/holehe && \
  python3 setup.py install

# sasquatch
RUN git clone --depth 1 https://github.com/devttys0/sasquatch.git /opt/sasquatch && \
  cd /opt/sasquatch && \
  wget https://patch-diff.githubusercontent.com/raw/devttys0/sasquatch/pull/47.patch -O 47.patch && \
  patch -p1 < 47.patch && \
  ./build.sh

# RsaCtfTool
RUN git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool && \
  cd /opt/RsaCtfTool && \
  python3 -m pip install -r requirements.txt

# xortool
RUN git clone --depth 1 https://github.com/hellman/xortool.git /opt/xortool

# Kyubi - dependency for nginxpwner
RUN git clone --depth 1 https://github.com/shibli2700/Kyubi.git /opt/kyubi && \
  cd /opt/kyubi && \
  python3 setup.py install

# nginxpwner
RUN git clone --depth 1 https://github.com/stark0de/nginxpwner.git /opt/nginxpwner && \
  cd /opt/nginxpwner && \
  python3 -m pip install -r requirements.txt

# NordVPN config
# https://support.nordvpn.com/Connectivity/Linux/1047409422/Connect-to-NordVPN-using-Linux-Terminal.htm
RUN wget -nv -O /tmp/nordvpn.zip https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip && \
  mkdir -p /etc/openvpn/nordvpn && \
  unzip /tmp/nordvpn.zip -d /etc/openvpn/nordvpn && \
  rm -f /tmp/nordvpn.zip

# LaZagneForensic
RUN git clone --depth 1 https://github.com/AlessandroZ/LaZagneForensic.git /opt/LaZagneForensic && \
  cd /opt/LaZagneForensic && \
  pip2 install markerlib && \
  pip2 install distribute && \
  pip2 install -r requirements.txt

# Burp
RUN wget -nv -O /opt/burp.jar https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar && \
  echo -e '#!/usr/bin/sh\njava -Xmx4g -jar /opt/burp.jar --disable-auto-update' > /usr/local/sbin/burp && \
  chmod +x /usr/local/sbin/burp

COPY docker-entrypoint.sh /usr/local/bin/

# cleanup
RUN go clean -modcache && \
  go clean -cache && \
  python3 -m pip cache purge && \
  rm -rf /root/.cargo/registry && \
  apt-get -y autoremove && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/*

# reset debian_frontend in the end
ENV DEBIAN_FRONTEND teletype

EXPOSE 80 443 8080 8443 9999 9090 1337

ENTRYPOINT ["docker-entrypoint.sh"]
