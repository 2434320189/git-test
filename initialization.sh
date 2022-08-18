#!/bin/bash
#This is initialization script of centos7!

fun1(){
    #设置固定ip
    echo "IPADDR=192.168.242.139" >> /etc/sysconfig/network-scripts/ifcfg-ens33
    
    #关闭防火墙
    systemctl stop firewalld 
    systemctl disable firewalld

    #关闭selinux
    setenforce 0
    sed "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/sysconfig/selinux -i
    sed "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config -i

    #ssh加固与优化
    mkdir -p /etc/ssh/back
    cp /etc/ssh/* back
    sed "s/#LogLevel INFO/LogLevel INFO/g" /etc/ssh/sshd_config -i
    sed "s/#ClientAliveInterval 0/ClientAliveInterval 900/g" /etc/ssh/sshd_config -i
    sed "s/#ClientAliveCountMax 3/ClientAliveCountMax 0/g" /etc/ssh/sshd_config -i
    sed "s/#MaxAuthTries 6/MaxAuthTries 6/g" /etc/ssh/sshd_config -i
    sed "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/g" /etc/ssh/sshd_config -i
    sed "s/#UseDNS yes/UseDNS no/g" /etc/ssh/sshd_config -i
    sed "s/GSSAPIAuthentication yes/GSSAPIAuthentication no/g" /etc/ssh/sshd_config -i

    #修改yum源和epel源
    yum -y install wget
    mkdir -p /etc/yum.repos.d/back
    cp /etc/yum.repos.d/* back
    wget -O /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
    wget -O /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo
    yum clean all && yum makecache

    #安装基础环境
    yum -y install vim gcc gcc-c++ \
    kernel-devel openssl tree net-tools \
    cmake pcre-devel pcre zlib zlib-devel

    #修改主机名
    hostnamectl set-hostname centos7-ran

    #网络时间同步
    yum install -y ntpdate
    ntpdate ntp.aliyun.com

    #创建普通用户white,并支持sudo
    useradd white 
    echo 243432 | passwd --stdin white
    sed '100a white    ALL=(ALL)       ALL' /etc/sudoers -i

    #内核参数调优
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    cp /etc/security/limits.conf /etc/security/limits.conf.bak

echo '
#表示系统级别的能够打开的文件句柄的数量。直接限制最大并发连接数。是对整个系统的限制，并不是针对用户的。
#ulimit -n 控制进程级别能够打开的文件句柄的数量。提供对shell及其启动的进程的可用文件句柄的控制。这是进程级别的。' >> /etc/sysctl.conf

echo -n '#file-max一般为内存大小（KB）的10%来计算：grep -r MemTotal /proc/meminfo | awk  ' >> /etc/sysctl.conf
echo "'{printf("'"%d",$2/10)}'"'" >> /etc/sysctl.conf
echo 'fs.file-max = 655360
 
#当每个网络接口接受数据包的速率比内核处理速率快时，允许发送到队列的数据包的最大数。
#默认值为300
net.core.netdev_max_backlog = 262144
 
#调节系统同时发起的TCP连接数。高并发情况下，该值越小，越容易出现超时情况。
#默认值为128
net.core.somaxconn = 262144
 
#设定系统中最多允许存在多少TCP套接字不被关联到任何一个用户文件句柄上。为了防止简单的DOS攻击。如果超过这个数字，孤立链接将立即被复位并输出警告信息。
#默认值为65535
net.ipv4.tcp_max_orphans = 262144
 
#记录尚未收到客户端确认信息的连接请求的最大值（三次握手建立阶段接受SYN请求）。设置大一些可使出现Nginx繁忙来不及接收新连接时，Linux不至于丢失客户端发起的链接请求。128M内存的服务器参数值为1024。
#默认值为1024
net.ipv4.tcp_max_syn_backlog = 262144
 
#设置内核放弃TCP连接之前向客户端发送SYN+ACK包的数据（三次握手中的第二次握手）。当为1时，内核在放弃连接之前再发送一次SYN+ACK包。
#默认值为5
net.ipv4.tcp_synack_retries = 1
 
#设置内核放弃建立连接之前向客户端发送SYN包的数据。
#默认值为5
net.ipv4.tcp_syn_retries = 1
 
#放大本地端口范围。
#默认值为32768 61000
net.ipv4.ip_local_port_range = 15000 65000
 
#表示某个TCP连接在空闲7200秒后，内核才发起探测，探测9次（每次75秒）不成功，内核才发送RST。清理无效链接。对服务器而言，默认值比较大，可结合业务调整。
#默认值为75/9/7200。
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_time = 1500
 
#启用 Cookies 来处理，可防范部分 SYN 攻击，当出现 SYN 等待队列溢出时也可继续连接。但开启后会使用 SHA1 验证 Cookies，理论上会增大 CPU 使用率。
#默认值为0
net.ipv4.tcp_syncookies = 1
 
#如果socket由服务端要求关闭，则该参数决定了保持在FIN-WAIT-2状态的时间。
#默认值为60
net.ipv4.tcp_fin_timeout = 30
 
#timewait的数量，最大值为262144。 如果超过这个数字，TIME_WAIT套接字将立刻被清除并打印警告信息。建议减小，避免TIME_WAIT状态过多消耗整个服务器的资源，但也不能太小，跟后端的处理速度有关，如果速度快可以小，速度慢则适当加大，否则高负载会有请求无法响应或非常慢。
#默认值为180000
net.ipv4.tcp_max_tw_buckets = 6000
 
#设置时间戳，避免序列号的卷绕。当为0时，禁用对于TCP时间戳的支持，针对Nginx服务器来说，建议关闭。
#默认值为1
net.ipv4.tcp_timestamps = 0
 
#TCP连接中TIME-WAIT的sockets快速回收功能。同时开启的话，缓存每个连接最新的时间戳，若后续的请求中时间戳小于缓存的时间戳时，该请求会被视为无效，导致数据包会被丢弃。
#不建议打开
#tcp_tw_recycle默认值为0
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_timestamps = 0
 
#允许将TIME-WAIT状态的sockets重新用于新的TCP连接，Nginx反向代理服务器（服务器即做客户端，也做server端时）
#tcp_tw_reuse默认值为0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 1
 
#以下4个参数，需要根据业务逻辑和实际的硬件成本来综合考虑
#内核接收套接字缓冲区大小的最大值（以字节为单位）
#缺省设置：110592
net.core.rmem_default = 6291456
 
#内核发送套接字缓冲区大小的缺省值（以字节为单位）
#可参考的优化值:873200/1746400/3492800
#缺省设置：110592
net.core.wmem_default = 6291456
 
#内核接收套接字缓冲区大小的最大值（以字节为单位）
#缺省设置：131071
net.core.rmem_max = 12582912
 
#内核发送套接字缓冲区大小的最大值（以字节为单位）
#缺省设置：131071
net.core.wmem_max = 12582912
 
#TCP接收socket请求缓存的内存最小值、默认值、最大值
net.ipv4.tcp_rmem = 10240 87380 12582912
 
#TCP发送socket请求缓存的内存最小值、默认值、最大值
net.ipv4.tcp_wmem = 10240 87380 12582912' >> /etc/sysctl.conf

    printf "* soft nproc 65536 \n* hard nproc 65536 \n* soft nofile 65536 \n* hard nofile 65536" >> /etc/security/limits.conf
    /sbin/sysctl -p

    #记录用户操作到指定文件
    cp /etc/profile /etc/profile.bak
    printf "\n" >> /etc/profile
    
echo  '#set user history
history
USER=`whoami`' >> /etc/profile
echo -n 'USER_IP=`who -u am i 2>/dev/null| awk '"'{"'print $NF'"}'"'|sed -e '"'s/[()]//g'" >> /etc/profile
echo '`' >> /etc/profile
echo 'if [ "$USER_IP" = "" ]; then
    USER_IP=`hostname`
fi
if [ ! -d /var/log/history ]; then
    mkdir /var/log/history
    chmod 777 /var/log/history
fi
if [ ! -d /var/log/history/${LOGNAME} ]; then
    mkdir /var/log/history/${LOGNAME}
    chown -R ${LOGNAME}:${LOGNAME} /var/log/history/${LOGNAME}
    chmod 770 /var/log/history/${LOGNAME}
fi
export HISTSIZE=4096
DT=`date +"%Y%m%d_%H:%M:%S"`
export HISTFILE="/var/log/history/${LOGNAME}/${USER}@${USER_IP}_$DT"
chmod 660 /var/log/history/${LOGNAME}/*history* 2>/dev/null' >> /etc/profile

    source /etc/profile

    #安装docker-ce-20.10.16-3.el7.x86_64
    yum install -y bash-completion lrzsz wget \
    expect net-tools nc nmap tree dos2unix htop \
    iftop iotop unzip telnet sl psmisc nethogs \
    glances bc ntpdate openldap-devel
    yum install -y yum-utils 
    yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
    yum clean all
    yum makecache

    yum install -y docker-ce-cli-20.10.16-3.el7.x86_64 \
    docker-scan-plugin-0.17.0-3.el7.x86_64 \
    docker-ce-20.10.16-3.el7.x86_64 \
    docker-ce-rootless-extras-20.10.16-3.el7.x86_64

    mkdir -p /etc/docker/
    touch /etc/docker/daemon.conf
    printf "{\n "registry-mirrors": ["https://registry.docker-cn.com"] \n}" > /etc/docker/daemon.conf
    systemctl daemon-reload
    systemctl start docker
    systemctl enable docker

    echo "脚本运行完毕！"
    echo "正在执行倒计时,预计10秒后重启"
    for((i=10;i>=0;i--))
    do
        if [ "$i" -gt "0" ];then
            echo "$i"
            sleep 1
        else
            echo "倒计时结束，重启中！"
            sleep 1
            reboot
        fi
    done
}

cat <<end
        请输入数字执行不同的操作：
        1.执行初始化脚本
        2.退出程序
end
read -p "请输入你的选择：" inp1

if [ "$inp1" == "1" ];then
    fun1
elif [ "$inp1" == "2" ];then
    exit 0
else
    echo "请输入规定的值!"
fi