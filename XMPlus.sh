#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

version="v1.0.0"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error: ${plain} This script must be run with the root user！\n" && exit 1

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
 
confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [Default$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "Whether to restart XMPlus" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press enter to return to the main menu: ${plain}" && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/xcode75/XMPlus/install/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    if [[ $# == 0 ]]; then
        echo && echo -n -e "Enter the specified version (default latest version): " && read version
    else
        version=$2
    fi
    bash <(curl -Ls https://raw.githubusercontent.com/xcode75/XMPlus/install/install.sh) $version
    if [[ $? == 0 ]]; then
        echo -e "${green}The update is complete and XMPlus has restarted automatically, please use XMPlus log to view the operation log${plain}"
        exit
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

config() {
    echo "XMPlus will automatically try to restart after modifying the configuration"
    vi /etc/XMPlus/config.yml
    sleep 2
    check_status
    case $? in
        0)
            echo -e "XMPlus Status: ${green}已运行${plain}"
            ;;
        1)
            echo -e "It is detected that you have not started XMPlus or XMPlus failed to restart automatically, check the log？[Y/n]" && echo
            read -e -p "(Default: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "XMPlus Status: ${red}Not Installed${plain}"
    esac
}

uninstall() {
    confirm "Are you sure you want to uninstall XMPlus?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop XMPlus
    systemctl disable XMPlus
    rm /etc/systemd/system/XMPlus.service -f
    systemctl daemon-reload
    systemctl reset-failed
    rm /etc/XMPlus/ -rf
    rm /usr/local/XMPlus/ -rf

    echo ""
    echo -e "The uninstallation is successful. If you want to delete this script, run ssh command ${green}rm -rf /usr/bin/XMPlus -f${plain} to delete"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${green}XMPlus aready running, no need to start again, if you need to restart, please select restart${plain}"
    else
        systemctl start XMPlus
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            echo -e "${green}XMPlus startup is successful, please use XMPlus log to view the operation log${plain}"
        else
            echo -e "${red}XMPlus may fail to start, please use XMPlus log to check the log information later${plain}"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    systemctl stop XMPlus
    sleep 2
    check_status
    if [[ $? == 1 ]]; then
        echo -e "${green}XMPlus stop successful${plain}"
    else
        echo -e "${red}XMPlus stop failed, probably because the stop time exceeded two seconds, please check the log information later${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    systemctl restart XMPlus
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        echo -e "${green}XMPlus restart is successful, please use XMPlus log to view the operation log${plain}"
    else
        echo -e "${red}XMPlus may fail to start, please use XMPlus log to check the log information later${plain}"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    systemctl status XMPlus --no-pager -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    systemctl enable XMPlus
    if [[ $? == 0 ]]; then
        echo -e "${green}start XMPlus on system boot successfully enabled${plain}"
    else
        echo -e "${red}start XMPlus on system boot failed to enable${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    systemctl disable XMPlus
    if [[ $? == 0 ]]; then
        echo -e "${green}diable XMPlus on system boot successfull${plain}"
    else
        echo -e "${red}diable XMPlus on system boot failed${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u XMPlus.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

install_bbr() {
    bash <(curl -L -s https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh)
}

update_shell() {
    wget -O /usr/bin/XMPlus -N --no-check-certificate https://raw.githubusercontent.com/xcode75/XMPlus/install/XMPlus.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${red}Failed to download the script, please check whether the machine can connect Github${plain}"
        before_show_menu
    else
        chmod +x /usr/bin/XMPlus
        echo -e "${green}The upgrade script was successful, please run the script again${plain}" && exit 0
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

check_enabled() {
    temp=$(systemctl is-enabled XMPlus)
    if [[ x"${temp}" == x"enabled" ]]; then
        return 0
    else
        return 1;
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}XMPlus already installed, please do not repeat the installation${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}please install XMPlus first${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "XMPlus Status: ${green}Running${plain}"
            show_enable_status
            ;;
        1)
            echo -e "XMPlus Status: ${yellow}Not Running${plain}"
            show_enable_status
            ;;
        2)
            echo -e "XMPlus Status: ${red}Not Installed${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Whether to start automatically: ${green}Yes${plain}"
    else
        echo -e "Whether to start automatically: ${red}No${plain}"
    fi
}

show_XMPlus_version() {
    echo -n "XMPlus Version："
    /usr/local/XMPlus/XMPlus -version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_usage() {
    echo "XMPlus management script: "
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

show_menu() {
    echo -e "
  ${green}XMPlus backend management script，${plain}${red}not applicable to docker${plain}
--- https://github.com/xcode75/XMPlus ---
  ${green}0.${plain} Change setting
————————————————
  ${green}1.${plain} Install XMPlus
  ${green}2.${plain} Update XMPlus
  ${green}3.${plain} Uninstall XMPlus
————————————————
  ${green}4.${plain} start XMPlus
  ${green}5.${plain} Stop XMPlus
  ${green}6.${plain} Restart XMPlus
  ${green}7.${plain} View XMPlus Status
  ${green}8.${plain} View XMPlus log
————————————————
  ${green}9.${plain} Enable XMPlus auto-satrt
 ${green}10.${plain} Disable XMPlus auto-satrt
————————————————
 ${green}11.${plain} One-click install bbr (latest kernel)
 ${green}12.${plain} View XMPlus version 
 ${green}13.${plain} Upgrade maintenance script
 "
 #后续更新可加入上方字符串中
    show_status
    echo && read -p "Please enter selection [0-13]: " num

    case "${num}" in
        0) config
        ;;
        1) check_uninstall && install
        ;;
        2) check_install && update
        ;;
        3) check_install && uninstall
        ;;
        4) check_install && start
        ;;
        5) check_install && stop
        ;;
        6) check_install && restart
        ;;
        7) check_install && status
        ;;
        8) check_install && show_log
        ;;
        9) check_install && enable
        ;;
        10) check_install && disable
        ;;
        11) install_bbr
        ;;
        12) check_install && show_XMPlus_version
        ;;
        13) update_shell
        ;;
        *) echo -e "${red}Please enter the correct number [0-12]${plain}"
        ;;
    esac
}


if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0
        ;;
        "stop") check_install 0 && stop 0
        ;;
        "restart") check_install 0 && restart 0
        ;;
        "status") check_install 0 && status 0
        ;;
        "enable") check_install 0 && enable 0
        ;;
        "disable") check_install 0 && disable 0
        ;;
        "log") check_install 0 && show_log 0
        ;;
        "update") check_install 0 && update 0 $2
        ;;
        "config") config $*
        ;;
        "install") check_uninstall 0 && install 0
        ;;
        "uninstall") check_install 0 && uninstall 0
        ;;
        "version") check_install 0 && show_XMPlus_version 0
        ;;
        "update_shell") update_shell
        ;;
        *) show_usage
    esac
else
    show_menu
fi