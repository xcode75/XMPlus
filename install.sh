#!/bin/bash

rm -rf $0

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)
 
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error：${plain} This script must be run with the root user！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}System version not detected, please contact the script author！${plain}\n" && exit 1
fi

arch=$(arch)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
  arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
  arch="arm64-v8a"
else
  arch="64"
  echo -e "${red}Failed to detect arch, use default arch: ${arch}${plain}"
fi

echo "arch: ${arch}"

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "This software does not support 32-bit system (x86), please use 64-bit system (x86_64), if the detection is wrong, please contact the author"
    exit 2
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Please use CentOS 7 or later!${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Please use Ubuntu 16 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Please use Debian 8 or higher！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
        yum install wget curl unzip tar crontabs socat -y
    else
        apt update -y
        apt install wget curl unzip tar cron socat -y
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/XMPlus.service ]]; then
        return 2
    fi
    temp=$(systemctl status XMPlus | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_acme() {
    curl https://get.acme.sh | sh
}

install_XMPlus() {
    if [[ -e /usr/local/XMPlus/ ]]; then
        rm /usr/local/XMPlus/ -rf
    fi

    mkdir /usr/local/XMPlus/ -p
	cd /usr/local/XMPlus/

    if  [ $# == 0 ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/xcode75/XMPlus/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to detect the XMPlus version, it may be because of Github API limit, please try again later, or manually specify the XMPlus version to install${plain}"
            exit 1
        fi
        echo -e "XMPlus latest version detected：${last_version}，Start Installation"
        wget -N --no-check-certificate -O /usr/local/XMPlus/XMPlus-linux.zip https://github.com/xcode75/XMPlus/releases/download/${last_version}/XMPlus-linux-${arch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMPlus failed，Please make sure your server can download github file${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/xcode75/XMPlus/releases/download/${last_version}/XMPlus-linux-${arch}.zip"
        echo -e "Start Installation XMPlus v$1"
        wget -N --no-check-certificate -O /usr/local/XMPlus/XMPlus-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMPlus v$1 failed, make sure this version exists${plain}"
            exit 1
        fi
    fi

    unzip XMPlus-linux.zip
    rm XMPlus-linux.zip -f
    chmod +x XMPlus
    mkdir /etc/XMPlus/ -p
    rm /etc/systemd/system/XMPlus.service -f
    file="https://raw.githubusercontent.com/xcode75/XMPlus/install/XMPlus.service"
    wget -N --no-check-certificate -O /etc/systemd/system/XMPlus.service ${file}
    #cp -f XMPlus.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl stop XMPlus
    systemctl enable XMPlus
    echo -e "${green}XMPlus ${last_version}${plain} The installation is complete，XMPlus has restarted"
    cp geoip.dat /etc/XMPlus/
    cp geosite.dat /etc/XMPlus/ 
	
    if [[ ! -f /etc/XMPlus/dns.json ]]; then
		cp dns.json /etc/XMPlus/
	fi
	if [[ ! -f /etc/XMPlus/route.json ]]; then 
		cp route.json /etc/XMPlus/
	fi
	
	if [[ ! -f /etc/XMPlus/outbound.json ]]; then
		cp outbound.json /etc/XMPlus/
	fi
	
	if [[ ! -f /etc/XMPlus/inbound.json ]]; then
		cp inbound.json /etc/XMPlus/
	fi

    if [[ ! -f /etc/XMPlus/config.yml ]]; then
        cp config.yml /etc/XMPlus/
    else
        systemctl start XMPlus
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}XMPlus restart successfully${plain}"
        else
            echo -e "${red} XMPlus May fail to start, please use [ XMPlus log ] View log information ${plain}"
        fi
    fi
    
    curl -o /usr/bin/XMPlus -Ls https://raw.githubusercontent.com/xcode75/XMPlus/install/XMPlus.sh
    chmod +x /usr/bin/XMPlus
    ln -s /usr/bin/XMPlus /usr/bin/xmplus 
    chmod +x /usr/bin/xmplus

    echo -e ""
    echo "XMPlus Management usage method: "
    echo "------------------------------------------"
    echo "XMPlus                    - Show menu (more features)"
    echo "XMPlus start              - Start XMPlus"
    echo "XMPlus stop               - Stop XMPlus"
    echo "XMPlus restart            - Restart XMPlus"
    echo "XMPlus status             - View XMPlus status"
    echo "XMPlus enable             - Enable XMPlus auto-start"
    echo "XMPlus disable            - Disable XMPlus auto-start"
    echo "XMPlus log                - View XMPlus logs"
    echo "XMPlus update             - Update XMPlus"
    echo "XMPlus update vx.x.x      - Update XMPlus Specific version"
    echo "XMPlus config             - Show configuration file content"
    echo "XMPlus install            - Install XMPlus"
    echo "XMPlus uninstall          - Uninstall XMPlus"
    echo "XMPlus version          	- View XMPlus version"
    echo "------------------------------------------"
}

echo -e "${green}Start Installation${plain}"
install_base
#install_acme
install_XMPlus $1
