# syntax=docker/dockerfile:1

FROM ubuntu:rolling
LABEL org.opencontainers.image.authors="firefart <firefart@gmail.com>"
LABEL org.opencontainers.image.title="dockerctf"
LABEL org.opencontainers.image.source="https://github.com/firefart/dockerctf"
LABEL org.opencontainers.image.description="Docker CTF image"

# https://go.dev/dl/
ARG GOLANG_VERSION="1.25.1"
ARG GOLANG_SHASUM="7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e"
# https://aws.amazon.com/corretto/
ARG JAVA_VERSION="25"
# https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu
ARG DOTNET_VERSION="9.0"
# https://github.com/nodesource/distributions
# https://nodejs.org/en/about/previous-releases#looking-for-the-latest-release-of-a-version-branch
ARG NODE_VERSION="24"

ENV HISTSIZE=5000
ENV HISTFILESIZE=10000
# looks like docker does not set this variable
ENV USER=root
ENV DEBIAN_FRONTEND=noninteractive
# disable .NET telemetry
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
# make vscode shut up
ENV DONT_PROMPT_WSL_INSTALL=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN echo "shopt -s histappend" >> /root/.bashrc

RUN apt-get update && \
  apt-get full-upgrade -y && \
  apt-get install -y --no-install-recommends \
  # tools
  git curl wget netcat-traditional socat build-essential tmux htop linux-headers-virtual dnsutils locales \
  software-properties-common apt-utils jq strace ltrace net-tools gdb gdb-multiarch binwalk steghide \
  testdisk foremost sqlite3 pev yara netmask libimage-exiftool-perl bsdmainutils unzip zsh aircrack-ng sudo \
  imagemagick genisoimage tree openvpn wireguard php crunch hydra gnupg2 tcpdump tor inotify-tools \
  colordiff hashcat inetutils-ping krb5-user whois cmake \
  # crackmapexec
  libxslt1-dev libxml2-dev \
  # binwalk
  lzop lhasa device-tree-compiler \
  # binwalkv3 https://github.com/ReFirmLabs/binwalk/blob/master/dependencies/ubuntu.sh
  p7zip-full zstd unzip tar sleuthkit cabextract curl wget git lz4 lzop device-tree-compiler \
  unrar unyaffs python3-pip build-essential clang liblzo2-dev libucl-dev liblz4-dev libbz2-dev \
  zlib1g-dev libfontconfig1-dev liblzma-dev libssl-dev \
  # sasquatch
  build-essential liblzma-dev liblzo2-dev zlib1g-dev \
  # JohnTheRipper
  libssl-dev zlib1g-dev yasm pkg-config libgmp-dev libpcap-dev libbz2-dev nvidia-opencl-dev \
  ocl-icd-opencl-dev opencl-headers pocl-opencl-icd \
  # scanning
  nmap masscan \
  # python stuff
  python3 python3-wheel python3-venv python3-requests python3-virtualenv \
  python3-bs4 python3-pip python3-scapy python3-pwntools \
  # python2
  libexpat1-dev libbz2-dev libreadline-dev libsqlite3-dev llvm libncurses-dev xz-utils tk-dev \
  # wpscan dependencies
  ruby ruby-dev zlib1g-dev liblzma-dev \
  # wfuzz dependencies
  python3-chardet python3-pycurl \
  # volatility dependencies
  pcregrep libpcre2-dev python3-dev python3-pefile python3-capstone python3-pycryptodome python3-yara \
  # angr deps
  python3-dev libffi-dev build-essential \
  # responder
  python3-netifaces \
  # arti deps
  sqlite3 libsqlite3-dev libssl-dev \
  # RsaCtfTool deps
  libmpfr-dev libmpc-dev \
  # android stuff
  android-sdk \
  # misc
  python3-winrm \
  # .NET SDK
  dotnet-sdk-${DOTNET_VERSION} \
  # google-chrome deps
  fonts-liberation libu2f-udev libvulkan1 xdg-utils \
  # OCR library
  tesseract-ocr libtesseract-dev \
  # musl
  musl musl-dev \
  # maigret
  libcairo2-dev \
  # sage (currently not supported on 24.04: https://launchpad.net/sagemath/+packages
  # sagemath sagemath-doc sagemath-jupyter \
  # metasploit
  git autoconf build-essential libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev libyaml-dev \
  # simavr
  gcc-avr binutils-avr gdb-avr avr-libc avrdude freeglut3-dev libelf-dev libncurses-dev pkg-config picocom \
  && \
  # google chrome as chromium needs snap to install
  wget -qO /tmp/google-chrome-stable_current_amd64.deb -nv "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" && \
  apt-get install -y --no-install-recommends /tmp/google-chrome-stable_current_amd64.deb && \
  rm -f /tmp/google-chrome-stable_current_amd64.deb && \
  # java (needs wget and software-properties-common from above)
  wget -qO- https://apt.corretto.aws/corretto.key | gpg --dearmor -o /etc/apt/keyrings/corretto-keyring.gpg && \
  echo "deb [signed-by=/etc/apt/keyrings/corretto-keyring.gpg] https://apt.corretto.aws stable main" > /etc/apt/sources.list.d/corretto.list && \
  apt-get update && \
  apt-get install -y --no-install-recommends java-${JAVA_VERSION}-amazon-corretto-jdk && \
  # nodejs
  apt-get install -y --no-install-recommends ca-certificates curl gnupg && \
  mkdir -p /etc/apt/keyrings && \
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_VERSION.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
  apt-get update && \
  apt-get install -y --no-install-recommends nodejs && \
  # vscode
  apt-get install -y --no-install-recommends wget gpg apt-transport-https && \
  wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/packages.microsoft.gpg && \
  echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list && \
  rm -f packages.microsoft.gpg && \
  # powershell not yet realased for latest ubuntu version
  # wget -qO /tmp/packages-microsoft-prod.deb "https://packages.microsoft.com/config/ubuntu/${lsb_release -sr}/packages-microsoft-prod.deb" && \
  # dpkg -i /tmp/packages-microsoft-prod.deb && \
  # rm -f /tmp/packages-microsoft-prod.deb && \
  apt-get update && \
  # apt-get install -y --no-install-recommends powershell && \
  apt-get install -y --no-install-recommends code && \
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
  --install-extension ms-dotnettools.csharp \
  --install-extension trailofbits.weaudit && \
  # remove unneeded packages
  apt-get -y autoremove && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/*

# set locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
  dpkg-reconfigure --frontend=noninteractive locales && \
  update-locale LANG=en_US.UTF-8

ENV LANG=en_US.UTF-8

# change default shell to zsh
RUN chsh -s /usr/bin/zsh

# aliases
RUN alias code="/usr/bin/code --user-data-dir='/root/.vscode' --no-sandbox" && \
  alias binwalk="/usr/bin/binwalk --run-as=root"

# dotfiles
RUN git clone --recurse-submodules --depth 1 https://github.com/firefart/dotfiles /opt/dotfiles && \
  cd /opt/dotfiles && \
  ./setup.sh

ENV EDITOR=nvim

# set nvim everywhere
RUN update-alternatives --install /usr/bin/editor editor /opt/neovim/bin/nvim 1 && \
  update-alternatives --set editor /opt/neovim/bin/nvim && \
  update-alternatives --install /usr/bin/vi vi /opt/neovim/bin/nvim 1 && \
  update-alternatives --set vi /opt/neovim/bin/nvim && \
  update-alternatives --install /usr/bin/vim vim /opt/neovim/bin/nvim 1 && \
  update-alternatives --set vim /opt/neovim/bin/nvim

# install go
RUN url="https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz" && \
  wget -qO go.tgz "$url" && \
  echo "${GOLANG_SHASUM} *go.tgz" | sha256sum -c - && \
  tar -C /usr/local -xzf go.tgz && \
  rm go.tgz

# uv and uvx (needed for getmail6)
COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

# rbenv
# hadolint ignore=SC2016
RUN git clone --depth 1 https://github.com/rbenv/rbenv.git /root/.rbenv && \
  git clone https://github.com/rbenv/ruby-build.git /root/.rbenv/plugins/ruby-build && \
  echo 'eval "$(/root/.rbenv/bin/rbenv init - zsh)"' >> ~/.zshrc && \
  echo "gem: --no-ri --no-rdoc" > /etc/gemrc

# rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# update PATH
ENV GOPATH="/root/go"
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin:/root/.local/bin:/root/.rbenv/bin:/root/.cargo/bin"
ENV TERM=xterm-256color

# python2
RUN wget -qO /tmp/python2.tar.xz "https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tar.xz" && \
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
  python2.7 -m pip install --no-cache-dir wheel requests pycryptodome

# binwalk fixes
RUN ln -s /usr/sbin/fsck.cramfs /usr/sbin/cramfsck && \
  uv tool install ubi_reader && \
  uv tool install jefferson && \
  uv tool install git+https://github.com/devttys0/yaffshiv.git

# sasquatch for binwalk
RUN git clone --depth 1 https://github.com/devttys0/sasquatch.git /opt/sasquatch && \
  cd /opt/sasquatch && \
  wget "https://patch-diff.githubusercontent.com/raw/devttys0/sasquatch/pull/47.patch" -qO 47.patch && \
  patch -p1 < 47.patch && \
  ./build.sh

# binwalkv3
RUN git clone --depth 1 https://github.com/ReFirmLabs/binwalk.git /opt/binwalkv3 && \
  cd /opt/binwalkv3 && \
  cargo build --release && \
  cp ./target/release/binwalk /usr/local/bin/binwalkv3

# metasploit framework
RUN git clone --depth 1 https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
  rbenv install "$(cat /opt/metasploit-framework/.ruby-version)" && \
  cd /opt/metasploit-framework && \
  gem install bundler && \
  # try to fix weird bundler error by installing this dep manually
  gem install xmlrpc && \
  bundle install

# feroxbuster
RUN wget -nv -O /tmp/x86_64-linux-feroxbuster.zip "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" && \
  unzip -qq -o /tmp/x86_64-linux-feroxbuster.zip -d /usr/bin && \
  chmod +x /usr/bin/feroxbuster && \
  rm -f /tmp/x86_64-linux-feroxbuster.zip

# wordlists
RUN mkdir /wordlists && \
  wget -nv -O /wordlists/rockyou.txt "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" && \
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
  git clone --depth 1 https://github.com/assetnote/commonspeak2-wordlists /wordlists/commonspeak2 && \
  git clone --depth 1 https://github.com/BuildHackSecure/gitscraper /wordlists/gitscraper && \
  wget -q -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -e robots=off --cut-dirs=1 -P /wordlists/assetnote

# go stuff
RUN go install github.com/OJ/gobuster/v3@dev && \
  go install github.com/ffuf/ffuf@latest && \
  go install github.com/jaeles-project/gospider@latest && \
  go install github.com/hakluke/hakrawler@latest && \
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
  go install github.com/tomnomnom/httprobe@latest && \
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
  go install github.com/firefart/aquatone@latest && \
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
  go install github.com/owasp-amass/amass/v4/...@latest && \
  go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest && \
  go install github.com/bloodhoundad/azurehound/v2@latest && \
  go clean -modcache && \
  go clean -cache && \
  # nuclei templates
  nuclei -update-templates

# Python3 tools
RUN true && \
  uv tool install oletools && \
  uv tool install angr && \
  uv tool install frida-tools && \
  uv tool install objection && \
  uv tool install pytesseract && \
  uv tool install roadrecon && \
  uv tool install roadtx && \
  uv tool install git+https://github.com/megadose/holehe.git && \
  uv tool install git+https://github.com/shibli2700/Kyubi.git && \
  uv tool install git+https://github.com/Pennyw0rth/NetExec.git && \
  uv tool install git+https://github.com/login-securite/lsassy.git && \
  uv tool install git+https://github.com/fortra/impacket.git && \
  uv tool install git+https://github.com/soxoj/maigret.git && \
  uv tool install git+https://github.com/sherlock-project/sherlock.git

# ruby stuff
RUN gem install wpscan evil-winrm

# Android and java stuff
RUN wget -nv -O /usr/local/bin/apktool "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" && \
  chmod +x /usr/local/bin/apktool && \
  wget -nv -O /usr/local/bin/apktool.jar "https://ghublatest.dev/latest/iBotPeaches/Apktool/apktool_*.jar" && \
  wget -nv -O /tmp/jadx.zip "https://ghublatest.dev/latest/skylot/jadx/jadx-*.zip" && \
  unzip -qq /tmp/jadx.zip -d /opt/jadx/ && \
  rm -f /tmp/jadx.zip && \
  wget -nv -O /opt/cfr.jar "https://ghublatest.dev/latest/leibnitz27/cfr/cfr-*.jar" && \
  wget -nv -O /tmp/dex2jar.zip "https://ghublatest.dev/latest/pxb1988/dex2jar/dex-tools-*.zip" && \
  unzip -qq /tmp/dex2jar.zip -d /opt/dex2jar/ && \
  rm -f /tmp/dex2jar.zip

# update PATH
ENV PATH="${PATH}:/opt/jadx/bin"

# various tools
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
  git clone --depth 1 https://github.com/lgandx/Responder /opt/responder && \
  git clone --depth 1 https://github.com/xmendez/wfuzz.git /opt/wfuzz && \
  git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database && \
  git clone --depth 1 https://github.com/hellman/xortool.git /opt/xortool

# volatility
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git /opt/volatility && \
  mkdir -p /opt/volatility/volatility/symbols/ && \
  wget -nv -O /opt/volatility/volatility/symbols/windows.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip" && \
  wget -nv -O /opt/volatility/volatility/symbols/mac.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip" && \
  wget -nv -O /opt/volatility/volatility/symbols/linux.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"

# volatility2
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility.git /opt/volatility2 && \
  python2.7 -m pip install --no-cache-dir distorm3==3.4.4 pycrypto openpyxl Pillow yara-python && \
  ln -fs /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

# gdb GEF
RUN wget -nv -O ~/.gdbinit-gef.py "https://raw.githubusercontent.com/hugsy/gef/main/gef.py" && \
  echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# pw cracking
RUN git clone --depth 1 https://github.com/magnumripper/JohnTheRipper.git /opt/JohnTheRipper && \
  cd /opt/JohnTheRipper/src && \
  ./configure --disable-native-tests && \
  make -s clean && \
  make -s -j "$(nproc)" && \
  make shell-completion

# NordVPN config
# https://support.nordvpn.com/Connectivity/Linux/1047409422/Connect-to-NordVPN-using-Linux-Terminal.htm
RUN wget -nv -O /tmp/nordvpn.zip "https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip" && \
  mkdir -p /etc/openvpn/nordvpn && \
  unzip -qq /tmp/nordvpn.zip -d /etc/openvpn/nordvpn && \
  rm -f /tmp/nordvpn.zip

# LaZagneForensic
RUN git clone --depth 1 https://github.com/AlessandroZ/LaZagneForensic.git /opt/LaZagneForensic && \
  python2.7 -m pip install --no-cache-dir markerlib && \
  python2.7 -m pip install --no-cache-dir distribute && \
  python2.7 -m pip install --no-cache-dir -r /opt/LaZagneForensic/requirements.txt

# Burp
RUN wget -nv -O /opt/burp.jar "https://portswigger-cdn.net/burp/releases/download?product=community&type=Jar" && \
  echo -e '#!/usr/bin/sh\njava -Xmx4g -jar /opt/burp.jar --disable-auto-update' > /usr/local/sbin/burp && \
  chmod +x /usr/local/sbin/burp

# Ghidra
RUN wget -nv -O /tmp/ghidra.zip "https://ghublatest.dev/latest/NationalSecurityAgency/ghidra/ghidra_*.zip" && \
  unzip -qq -o /tmp/ghidra.zip -d /tmp && \
  mv /tmp/ghidra_* /opt/ghidra && \
  rm -f /tmp/ghidra.zip

# simavr
RUN git clone --depth 1 https://github.com/buserror/simavr /opt/simavr && \
  cd /opt/simavr && \
  make -s clean && \
  make -s -j "$(nproc)" AVR_ROOT=/usr/lib/avr && \
  make -s install
ENV SIMAVR_UART_XTERM=1

# radare2
RUN git clone --depth 1 https://github.com/radareorg/radare2 /opt/radare2 && \
  cd /opt/radare2 && \
  ./sys/install.sh && \
  mkdir -p /usr/share/radare2/ && \
  echo "e asm.describe = true" > /usr/share/radare2/radare2rc

# sharphound
# https://go.dev/play/p/gn89ONb61T8
RUN wget -nv -O /tmp/sharphound.zip "https://ghublatest.dev/latest/SpecterOps/SharpHound/SharpHound_v*[^+debug]_windows_x86.zip" && \
  mkdir -p /opt/sharphound && \
  unzip -qq -o /tmp/sharphound.zip -d /opt/sharphound && \
  rm -f /tmp/sharphound.zip

COPY docker-entrypoint.sh /usr/local/bin/

# reset debian_frontend in the end
ENV DEBIAN_FRONTEND=teletype

EXPOSE 80 443 1234 4444 8080 8443 9999 9090 1337

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
