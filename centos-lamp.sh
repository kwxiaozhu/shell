#!/bin/bash
function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/redhat-release ]
    then
        die "Distribution is not supported"
    fi
}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}


function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/random-seed
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_lamp() {
	yum -y install  mysql-server  httpd mod_fcgid php-cli php-curl php-gd php-sqlite php-mysql
	service mysqld stop
	service httpd stop
# setup httpd
    mkdir /etc/httpd/sites
    chmod 700 -R /etc/httpd/sites
    cat >>/etc/httpd/conf/httpd.conf<<ENDL
Include sites/*
ENDL
    cat >>/etc/httpd/conf.d/fcgid.conf<<ENDL
<IfModule mod_fcgid.c>
AddHandler fcgid-script .php .py .pl .fcgi
FcgidConnectTimeout 60
FcgidIdleTimeout 60
FcgidProcessLifeTime 600
FcgidMaxRequestsPerProcess 4000
FcgidMaxProcesses 10
FcgidMinProcessesPerClass 2
FcgidMaxProcessesPerClass 5
FcgidIOTimeout 600
FcgidBusyTimeout 600
FcgidFixPathinfo 1
</IfModule>
ENDL

# setup mysql    
    rm -f /var/lib/mysql/ib*
    cat > /etc/my.cnf <<END
[mysqld]
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
user=mysql
# Disabling symbolic-links is recommended to prevent assorted security risks
bind-address=127.0.0.1
symbolic-links=0
key_buffer = 8M
query_cache_size = 0
skip-innodb

[mysqld_safe]
log-error=/var/log/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid

END
	service mysqld start
#	sleep 2s
    # Generating a new password for the root user.
	passwd=`get_password root@mysql`
    mysqladmin -uroot  password "$passwd"
rm -rf ~/.my.cnf
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
	cat > ~/temp.sql <<END
delete from user where user='' or password='';
flush privileges;
END
	mysql -uroot -p"$passwd" mysql<temp.sql
	rm -rf ~/temp.sql
    chmod 600 ~/.my.cnf
	service mysqld restart

# setup complete
	service mysqld start
	service httpd start
	chkconfig mysqld on
	chkconfig httpd on
}

function install_vhost {
	if [ ! -d /var/www/sites ];
        then
        mkdir /var/www/sites
	fi
    chmod 711 /var/www/sites
    read -p "Please input domain:" domain
    read -p "Please input username:" username
    if [ -f "/etc/httpd/sites/$username" ]; then
    echo "Username exist,please enter another!"
    exit 1
    fi
 
    useradd -s /usr/sbin/nologin -d /var/www/sites/$username $username 
    mkdir -p /var/www/sites/$username/{public_html,sessions,tmp,conf,logs}
	chown -R $username:$username /var/www/sites/$username
	chown $username:apache /var/www/sites/$username/public_html
	
	chmod 710 /var/www/sites/$username/public_html
	chmod 700 /var/www/sites/$username/logs
	
    cat >/etc/httpd/sites/$username<<eof
    <VirtualHost *:80>
            ServerAdmin webmaster@localhost
            ServerName      $domain
            DocumentRoot /var/www/sites/$username/public_html
            SuexecUserGroup $username $username
            FcgidWrapper /var/www/sites/$username/conf/php-cgi .php
    #       FcgidInitialEnv "/var/www/sites/$username/conf"
            <Directory />
                    DirectoryIndex index.php index.html
                    Options ExecCGI Indexes FollowSymLinks MultiViews
                    AllowOverride all
            </Directory>
            ErrorLog /var/www/sites/$username/logs/error-$username.log
            LogLevel warn
            CustomLog /var/www/sites/$username/logs/access-$username.log combined
    </VirtualHost>
eof
    
cat >/var/www/sites/$username/conf/php-cgi<<end
    #!/bin/sh
    export PHPRC="/var/www/sites/$username/conf/"
    #export PHP_FCGI_MAX_REQUESTS=1000
    #export PHP_FCGI_CHILDREN=5
    #exec /usr/lib/cgi-bin/php
    exec /usr/bin/php-cgi
end
    cat >/var/www/sites/$username/conf/php.ini<<start
    [PHP]
    short_open_tag=On
    register_globals=Off
    magic_quotes_gpc=On
    post_max_size = 20M
    upload_max_filesize = 20M
    allow_url_fopen = On
    memory_limit=64M
    max_execution_time=30
    default_socket_timeout=60
    display_errors = off
    register_argc_argv = on
     
    open_basedir = /var/www/sites/$username/public_html:/var/www/sites/$username/tmp/:/proc
    upload_tmp_dir = /var/www/sites/$username/tmp
    soap.wsdl_cache_dir = /var/www/sites/$username/tmp
    session.save_path = /var/www/sites/$username/sessions
start
    wget -q -P "/var/www/sites/$username/public_html" http://github.com/kwxiaozhu/shell/raw/master/tz.php
    chmod +x /var/www/sites/$username/conf/php-cgi
    echo "vhost add success!"
    echo "doamin is:$domain"
    echo "username is:$username"
    echo "vhost directory is: /var/www/sites/$username/public_html"
    service httpd reload
}

function install_vsftpd {
	yum -y install vsftpd db4-utils
	service vsftpd stop
	mv /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
	cat >/etc/vsftpd/vsftpd.conf <<END
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=NO
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES
ftpd_banner=Welcome to FTP service.
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd.vu
rsa_cert_file=/etc/ssl/private/vsftpd.pem
user_config_dir=/etc/vsftpd_user_conf
guest_enable=YES
guest_username=nginx	
END
	cat >/etc/pam.d/vsftpd.vu <<END
auth	required	pam_userdb.so	db=/etc/vsftpd_login
account required	pam_userdb.so	db=/etc/vsftpd_login
END
	if [ ! -d /etc/vsftpd_user_conf ];
        then
        mkdir /etc/vsftpd_user_conf
	fi
	if [ ! -d /var/run/vsftpd/empty ];
		then
		mkdir -p /var/run/vsftpd/empty
	fi
	passwd=`get_password vsftpd`
	cat >~/.loguser.txt <<END
admin
$passwd
END
	db_load -T -t hash -f ~/.loguser.txt /etc/vsftpd_login.db
	cat >/etc/vsftpd_user_conf/admin <<END
local_root=/var/www/
write_enable=YES
anon_umask=022
anon_world_readable_only=NO
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
END
	chmod 600 ~/.loguser.txt
	chmod 600 /etc/vsftpd_login.db
	chmod 600 /etc/vsftpd_user_conf -R
	service vsftpd start
	echo 'vsftpd setup complete!'
	echo 'admin account is admin,password is in password file,home directory is /home/www'
	echo 'password file stored in .loguser.txt'
}

function remove_unneeded {
	yum -y remove httpd* php* samba* bind9* nscd
	service saslauthd stop
	service xinetd stop
	service udev-post stop
	chkconfig udev-post off
	chkconfig saslauthd off
	chkconfig xinetd off
}

function update_upgrade {
    # Run through the yum  update first. This should be done before
    # we try to install any package

rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm	
yum update -y
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
lnmp)
    install_lamp
    ;;
system)
    remove_unneeded
    update_upgrade
    ;;
vhost)
    install_vhost 
    ;;
ssh)
#    cat >> /etc/shells <<END
#/bin/false
#END
	useradd $2 -M -s /bin/false
	echo $2:$3 | chpasswd 
    ;;
vsftpd)
	install_vsftpd
	;;
sshport)
	#sed -i  s/'Port 22'/'Port kwxiaozhu'/ /etc/ssh/sshd_config
	sed -i  s/'^#Port [0-9]*'/'Port kwxiaozhu'/ /etc/ssh/sshd_config
	sed -i s/kwxiaozhu/$2/ /etc/ssh/sshd_config
	service sshd restart
	;;
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in system lnmp vhost vsftpd ssh sshport
    do
        echo '  -' $option
    done
    ;;
esac
