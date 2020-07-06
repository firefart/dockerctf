FROM ubuntu:latest
LABEL maintainer="firefart <firefart@gmail.com>"

ARG GOLANG_VERSION="1.14.4"
ARG GOLANG_SHASUM="aed845e4185a0b2a3c3d5e1d0a35491702c55889192bb9c30e67a3de6849c067"
ARG APKTOOL_VERSION="2.4.1"
ARG JAVA_VERSION="11"
ARG JADX_VERSION="1.1.0"

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
  jq strace ltrace net-tools gdb gdb-multiarch binwalk steghide testdisk foremost sqlite3 pev yara \
  # scanning
  nmap masscan \
  # python stuff
  python2 python3 python3-wheel python3-requests python3-virtualenv python3-bs4 python3-pip python3-pycryptodome \
  # wpscan dependencies
  ruby ruby-dev rubygems zlib1g-dev liblzma-dev \
  # wfuzz dependencies
  python3-chardet python3-pycurl python3-future \
  # volatility dependencies
  pcregrep libpcre++-dev python2-dev python3-dev python3-pefile python3-yara python3-capstone \
  && \
  # java (needs wget and software-properties-common from above)
  wget -nv -O- https://apt.corretto.aws/corretto.key | apt-key add - && \
  add-apt-repository 'deb https://apt.corretto.aws stable main' && \
  apt-get update && apt-get install -y java-${JAVA_VERSION}-amazon-corretto-jdk && \
  # remove unneeded packages
  apt-get -y autoremove

# Install PIP2 and packages (are not available on the repo)
RUN curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py && \
  python2 /tmp/get-pip.py
RUN pip2 install requests pycryptodome

# make sure we can use python to launch python3
RUN update-alternatives --install /usr/local/bin/python python /usr/bin/python3 1
RUN update-alternatives --install /usr/local/bin/pip pip /usr/bin/pip3 1

# wordlists
RUN mkdir /wordlists && \
  wget -nv -O /wordlists/rockyou.txt https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt && \
  wget -nv -O /wordlists/directory-list-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-small.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-big.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-big.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-medium.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-medium.txt && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-small.txt https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-small.txt

# SecLists
RUN git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

RUN git clone https://github.com/FlameOfIgnis/Pwdb-Public.git /opt/Pwdb-Public

# oh my tmux
ENV TERM=xterm-256color
RUN git clone https://github.com/gpakosz/.tmux.git /root/.tmux && \
  ln -s -f /root/.tmux/.tmux.conf /root/.tmux.conf && \
  cp /root/.tmux/.tmux.conf.local /root/

# dotfiles
RUN git clone https://github.com/FireFart/dotfiles /opt/dotfiles && \
  cd /opt/dotfiles && \
  ./setup.sh

# install go
RUN url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz"; \
	wget -O go.tgz -nv "$url"; \
	echo "${GOLANG_SHASUM} *go.tgz" | sha256sum -c -; \
	tar -C /usr/local -xzf go.tgz; \
	rm go.tgz;

# update PATH
ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"

# gobuster
RUN git clone --branch v3.1-cleaned https://github.com/OJ/gobuster.git /opt/gobuster && \
  cd /opt/gobuster && \
  go get . && \
  go build && \
  go install

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

# update PATH
ENV PATH="${PATH}:/opt/jadx/bin"

# sqlmap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# wfuzz
RUN git clone https://github.com/xmendez/wfuzz.git /opt/wfuzz

# volatility
RUN git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility && \
  wget -nv -O /opt/volatility/volatility/symbols/windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip && \
  wget -nv -O /opt/volatility/volatility/symbols/mac.zip https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip && \
  wget -nv -O /opt/volatility/volatility/symbols/linux.zip https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip

# volatility2
RUN git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility2 && \
  pip2 install distorm3==3.4.4 pycrypto openpyxl Pillow

# libc-database
RUN git clone https://github.com/niklasb/libc-database.git /opt/libc-database

# reset debian_frontend in the end
ENV DEBIAN_FRONTEND teletype

ENTRYPOINT [ "/bin/bash" ]
