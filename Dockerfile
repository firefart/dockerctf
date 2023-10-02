FROM ubuntu:rolling
LABEL org.opencontainers.image.authors="firefart <firefart@gmail.com>"
LABEL org.opencontainers.image.title="dockerctf"
LABEL org.opencontainers.image.source="https://github.com/firefart/dockerctf"
LABEL org.opencontainers.image.description="Docker CTF image"

# https://go.dev/dl/
ARG GOLANG_VERSION="1.21.1"
ARG GOLANG_SHASUM="b3075ae1ce5dab85f89bc7905d1632de23ca196bd8336afd93fa97434cfa55ae"
# https://aws.amazon.com/corretto/
ARG JAVA_VERSION="21"

# https://github.com/iBotPeaches/Apktool/releases/latest
ARG APKTOOL_VERSION="2.8.1"
# https://github.com/skylot/jadx/releases/latest
ARG JADX_VERSION="1.4.7"
# https://github.com/leibnitz27/cfr/releases/latest
ARG CFR_VERSION="0.152"
# https://github.com/pxb1988/dex2jar/releases/latest
ARG DEX2JAR_VERSION="2.3"
# https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu
ARG DOTNET_VERSION="7.0"
# https://portswigger.net/burp/releases/community/latest
ARG BURP_VERSION="2023.10.1.2"
# https://github.com/NationalSecurityAgency/ghidra/releases/latest
ARG GHIDRA_VERSION="10.4"
ARG GHIDRA_DATE="20230928"
# https://github.com/nodesource/distributions#debian-and-ubuntu-based-distributions
ARG NODE_VERSION="20"

ENV HISTSIZE=5000
ENV HISTFILESIZE=10000
# looks like docker does not set this variable
ENV USER=root
ENV DEBIAN_FRONTEND noninteractive
# disable .NET telemetry
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
# make vscode shut up
ENV DONT_PROMPT_WSL_INSTALL=1

RUN echo "shopt -s histappend" >> /root/.bashrc

RUN apt-get update && \
  apt-get full-upgrade -y && \
  apt-get install -y \
  # tools
  git curl wget netcat-traditional socat build-essential tmux vim htop linux-headers-virtual dnsutils \
  software-properties-common apt-utils jq strace ltrace net-tools gdb gdb-multiarch binwalk steghide \
  testdisk foremost sqlite3 pev yara netmask exiftool bsdmainutils unzip zsh aircrack-ng \
  imagemagick mkisofs tree openvpn wireguard php crunch hydra gnupg2 tcpdump tor \
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
  python3-bs4 python3-pip pipx python3-scapy python3-pwntools \
  # python2
  libexpat1-dev libbz2-dev libreadline-dev libsqlite3-dev llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev \
  # wpscan dependencies
  ruby ruby-dev rubygems zlib1g-dev liblzma-dev \
  # wfuzz dependencies
  python3-chardet python3-pycurl python3-future \
  # volatility dependencies
  pcregrep libpcre2-dev python3-dev python3-pefile python3-capstone python3-pycryptodome python3-yara \
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
  # OCR library
  tesseract-ocr libtesseract-dev \
  # musl
  musl musl-dev \
  # sage
  sagemath sagemath-doc sagemath-jupyter \
  # metasploit
  git autoconf build-essential libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev \
  && \
  # google chrome as chromium needs snap to install
  wget -O /tmp/google-chrome-stable_current_amd64.deb -nv "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" && \
  apt-get install -y /tmp/google-chrome-stable_current_amd64.deb && \
  rm -f /tmp/google-chrome-stable_current_amd64.deb && \
  # java (needs wget and software-properties-common from above)
  wget -nv -O- "https://apt.corretto.aws/corretto.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/corretto.gpg && \
  add-apt-repository 'deb https://apt.corretto.aws stable main' && \
  apt-get update && \
  apt-get install -y java-${JAVA_VERSION}-amazon-corretto-jdk && \
  # nodejs
  apt-get install -y ca-certificates curl gnupg && \
  mkdir -p /etc/apt/keyrings && \
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_VERSION.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
  apt-get update && \
  apt-get install nodejs -y && \
  # vscode
  apt-get install -y wget gpg apt-transport-https && \
  wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && \
  install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg  && \
  echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list && \
  rm -f packages.microsoft.gpg && \
  apt-get update && \
  apt-get install -y code && \
  # install vscode extensions
  code --user-data-dir="/root/.vscode" --no-sandbox \
  --install-extension golang.Go \
  --install-extension ms-vscode.PowerShell \
  --install-extension esbenp.prettier-vscode \
  --install-extension ms-python.python \
  --install-extension snyk-security.snyk-vulnerability-scanner \
  --install-extension redhat.vscode-yaml \
  --install-extension redhat.vscode-xml \
  --install-extension ms-vscode.cpptools \
  --install-extension ms-dotnettools.csharp && \
  # remove unneeded packages
  apt-get -y autoremove && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/*

# change default shell to zsh
SHELL ["/usr/bin/zsh", "-c"]
RUN chsh -s /usr/bin/zsh

RUN alias code="/usr/bin/code --user-data-dir='/root/.vscode' --no-sandbox"

# install go
RUN url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz" && \
  wget -O go.tgz -nv "$url" && \
  echo "${GOLANG_SHASUM} *go.tgz" | sha256sum -c - && \
  tar -C /usr/local -xzf go.tgz && \
  rm go.tgz

# update PATH
ENV GOPATH="/root/go"
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"

# oh my tmux
ENV TERM=xterm-256color
RUN git clone --depth 1 https://github.com/gpakosz/.tmux.git /root/.tmux && \
  ln -s -f /root/.tmux/.tmux.conf /root/.tmux.conf && \
  cp /root/.tmux/.tmux.conf.local /root/

# dotfiles
RUN git clone --depth 1 https://github.com/firefart/dotfiles /opt/dotfiles && \
  cd /opt/dotfiles && \
  ./setup.sh

# rbenv
RUN git clone --depth 1 https://github.com/rbenv/rbenv.git /root/.rbenv && \
  git clone https://github.com/rbenv/ruby-build.git /root/.rbenv/plugins/ruby-build && \
  echo 'eval "$(/root/.rbenv/bin/rbenv init - zsh)"' >> ~/.zshrc && \
  echo "gem: --no-ri --no-rdoc" > /etc/gemrc

ENV PATH="${PATH}:/root/.rbenv/bin"

# python2
RUN wget -O /tmp/python2.tar.xz -nv "https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tar.xz" && \
  mkdir -p /usr/src/python2 && \
  tar --extract --directory /usr/src/python2 --strip-components=1 --file /tmp/python2.tar.xz && \
  rm -f /tmp/python2.tar.xz && \
  cd /usr/src/python2 && \
  ./configure --enable-optimizations --enable-option-checking=fatal --with-ensurepip=install --enable-shared --with-lto --with-system-expat && \
  make -s -j "$(nproc)" && \
  make altinstall && \
  make clean && \
  ldconfig && \
  # Install python2 packages
  python2.7 -m pip install wheel requests pycryptodome

# rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

# metasploit framework
RUN git clone --depth 1 https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
  rbenv install $(cat /opt/metasploit-framework/.ruby-version) && \
  cd /opt/metasploit-framework && \
  gem install bundler && \
  bundle install

# feroxbuster
RUN wget -nv -O /tmp/x86_64-linux-feroxbuster.zip "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" && \
  unzip -o /tmp/x86_64-linux-feroxbuster.zip -d /usr/bin && \
  chmod +x /usr/bin/feroxbuster && \
  rm -f /tmp/x86_64-linux-feroxbuster.zip

# wordlists
RUN mkdir /wordlists && \
  wget -nv -O /wordlists/rockyou.txt "https://www.scrapmaker.com/data/wordlists/dictionaries/rockyou.txt" && \
  wget -nv -O /wordlists/directory-list-2.3-big.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-big.txt" && \
  wget -nv -O /wordlists/directory-list-2.3-medium.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-medium.txt" && \
  wget -nv -O /wordlists/directory-list-2.3-small.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-2.3-small.txt" && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-big.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-big.txt" && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-medium.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-medium.txt" && \
  wget -nv -O /wordlists/directory-list-lowercase-2.3-small.txt "https://github.com/dustyfresh/dictionaries/raw/master/DirBuster-Lists/directory-list-lowercase-2.3-small.txt" && \
  wget -nv -O /wordlists/jhaddix-all.txt "https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" && \
  wget -nv -O /wordlists/fuzz.txt "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt" && \
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git /wordlists/SecLists && \
  git clone --depth 1 https://github.com/FlameOfIgnis/Pwdb-Public.git /wordlists/Pwdb-Public && \
  git clone --depth 1 https://github.com/assetnote/commonspeak2-wordlists /wordlists/commonspeak2

# go stuff
RUN go install github.com/OJ/gobuster/v3@dev && \
  go install github.com/ffuf/ffuf@latest && \
  go install github.com/jaeles-project/gospider@latest && \
  go install github.com/hakluke/hakrawler@latest && \
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
  go install github.com/tomnomnom/httprobe@latest && \
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
  go install github.com/firefart/aquatone@latest && \
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
  go install github.com/owasp-amass/amass/v4/...@latest && \
  go clean -modcache && \
  go clean -cache

# Python3 tools
RUN python3 -m pip install --break-system-packages oletools angr frida-tools objection pytesseract && \
  git clone --depth 1 https://github.com/yassineaboukir/Asnlookup /opt/asnlookup && \
  python3 -m pip install --break-system-packages -r /opt/asnlookup/requirements.txt && \
  git clone --depth 1 https://github.com/orlyjamie/asnrecon /opt/asnrecon && \
  python3 -m pip install --break-system-packages -r /opt/asnrecon/requirements.txt && \
  git clone --depth 1 https://github.com/vysecurity/DomLink.git /opt/domlink && \
  python3 -m pip install --break-system-packages -r /opt/domlink/requirements.txt && \
  git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/subdomainizer && \
  python3 -m pip install --break-system-packages -r /opt/subdomainizer/requirements.txt && \
  git clone --depth 1 https://github.com/x90skysn3k/brutespray.git /opt/brutespray && \
  python3 -m pip install --break-system-packages -r /opt/brutespray/requirements.txt && \
  git clone --depth 1 https://github.com/sherlock-project/sherlock /opt/sherlock && \
  python3 -m pip install --break-system-packages -r /opt/sherlock/requirements.txt && \
  git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool && \
  python3 -m pip install --break-system-packages -r /opt/RsaCtfTool/requirements.txt && \
  git clone --depth 1 https://github.com/stark0de/nginxpwner.git /opt/nginxpwner && \
  python3 -m pip install --break-system-packages -r /opt/nginxpwner/requirements.txt && \
  python3 -m pip cache purge

# wpscan
RUN gem install wpscan

# apktool
RUN wget -nv -O /usr/local/bin/apktool "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" && \
  chmod +x /usr/local/bin/apktool && \
  wget -nv -O /usr/local/bin/apktool.jar "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar"

# jadx
RUN wget -nv -O /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
  unzip -qq /tmp/jadx.zip -d /opt/jadx/ && \
  rm -f /tmp/jadx.zip

# CFR java decompiler
RUN wget -nv -O /opt/cfr.jar "https://github.com/leibnitz27/cfr/releases/download/${CFR_VERSION}/cfr-${CFR_VERSION}.jar"

# update PATH
ENV PATH="${PATH}:/opt/jadx/bin"

# dex2jar
RUN wget -nv -O /tmp/dex2jar.zip  "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex2jar-v2.zip" && \
  unzip -qq /tmp/dex2jar.zip -d /opt/dex2jar/ && \
  rm -f /tmp/dex2jar.zip

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# wfuzz
RUN git clone --depth 1 https://github.com/xmendez/wfuzz.git /opt/wfuzz

# volatility
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git /opt/volatility && \
  mkdir -p /opt/volatility/volatility/symbols/ && \
  wget -nv -O /opt/volatility/volatility/symbols/windows.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip" && \
  wget -nv -O /opt/volatility/volatility/symbols/mac.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip" && \
  wget -nv -O /opt/volatility/volatility/symbols/linux.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"

# volatility2
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility.git /opt/volatility2 && \
  python2.7 -m pip install distorm3==3.4.4 pycrypto openpyxl Pillow yara-python && \
  ln -fs /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

# libc-database
RUN git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database

# gdb GEF
RUN wget -nv -O ~/.gdbinit-gef.py "https://raw.githubusercontent.com/hugsy/gef/master/gef.py" && \
  echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# pw cracking
RUN git clone --depth 1 https://github.com/magnumripper/JohnTheRipper.git /opt/JohnTheRipper && \
  cd /opt/JohnTheRipper/src && \
  ./configure --disable-native-tests && \
  make -s clean && \
  make -s -j "$(nproc)" && \
  make shell-completion

# holehe
RUN pipx install git+https://github.com/megadose/holehe.git

# sasquatch
RUN git clone --depth 1 https://github.com/devttys0/sasquatch.git /opt/sasquatch && \
  cd /opt/sasquatch && \
  wget "https://patch-diff.githubusercontent.com/raw/devttys0/sasquatch/pull/47.patch" -O 47.patch && \
  patch -p1 < 47.patch && \
  ./build.sh

# xortool
RUN git clone --depth 1 https://github.com/hellman/xortool.git /opt/xortool

# Kyubi - dependency for nginxpwner
ENV PATH="${PATH}:/root/.local/bin"
RUN pipx install git+https://github.com/shibli2700/Kyubi.git

# NordVPN config
# https://support.nordvpn.com/Connectivity/Linux/1047409422/Connect-to-NordVPN-using-Linux-Terminal.htm
RUN wget -nv -O /tmp/nordvpn.zip "https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip" && \
  mkdir -p /etc/openvpn/nordvpn && \
  unzip /tmp/nordvpn.zip -d /etc/openvpn/nordvpn && \
  rm -f /tmp/nordvpn.zip

# Hackinglab VPN
RUN git clone --depth 1 https://github.com/Hacking-Lab/hl2-openvpn-ost.ch.git /opt/hackinglab_vpn/ && \
  # we have no sudo available inside docker so patch it out
  sed -i 's/sudo //g' /opt/hackinglab_vpn/start_openvpn.sh

# LaZagneForensic
RUN git clone --depth 1 https://github.com/AlessandroZ/LaZagneForensic.git /opt/LaZagneForensic && \
  python2.7 -m pip install markerlib && \
  python2.7 -m pip install distribute && \
  python2.7 -m pip install -r /opt/LaZagneForensic/requirements.txt

# Burp
RUN wget -nv -O /opt/burp.jar "https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar" && \
  echo -e '#!/usr/bin/sh\njava -Xmx4g -jar /opt/burp.jar --disable-auto-update' > /usr/local/sbin/burp && \
  chmod +x /usr/local/sbin/burp

# Ghidra
RUN wget -nv -O /tmp/ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
  unzip -o /tmp/ghidra.zip -d /tmp && \
  mv /tmp/ghidra_* /opt/ghidra

COPY docker-entrypoint.sh /usr/local/bin/

# reset debian_frontend in the end
ENV DEBIAN_FRONTEND teletype

EXPOSE 80 443 1234 4444 8080 8443 9999 9090 1337

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
