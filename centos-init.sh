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

function install_lnmp() {
	yum -y install  mysql-server  nginx php-fpm php-curl php-gd php-sqlite php-mysql
	service mysqld stop
	service php-fpm stop
	service nginx stop
# setup php5
	rm -rf /var/www
	mkdir -p /var/www
	wget -P "/var/www/" https://github.com/kwxiaozhu/shell/raw/master/tz.php
    chown apache:apache -R /var/www
	sed -i  s/'listen = 127.0.0.1:9000'/'listen = \/var\/run\/php5-fpm.sock'/ /etc/php-fpm.d/www.conf
#	sed -i  s/'pm = dynamic'/'pm = static'/ /etc/php-fpm.d/www.conf
	sed -i  s/'^pm.max_children = [0-9]*'/'pm.max_children = 5'/ /etc/php-fpm.d/www.conf
	sed -i  s/'^pm.start_servers = [0-9]*'/'pm.start_servers = 3'/ /etc/php-fpm.d/www.conf
	sed -i  s/'^pm.min_spare_servers = [0-9]*'/'pm.min_spare_servers = 2'/ /etc/php-fpm.d/www.conf
	sed -i  s/'^pm.max_spare_servers = [0-9]*'/'pm.max_spare_servers = 5'/ /etc/php-fpm.d/www.conf
	sed -i  s/'user = apache'/'user = nobody'/ /etc/php-fpm.d/www.conf
	sed -i  s/'group = apache'/'group = nobody'/ /etc/php-fpm.d/www.conf
	sed -i  s/'memory_limit = 128M'/'memory_limit = 64M'/ /etc/php.ini
	sed -i  s/'short_open_tag = Off'/'short_open_tag = On'/ /etc/php.ini
	sed -i  s/'upload_max_filesize = 2M'/'upload_max_filesize = 8M'/ /etc/php.ini
	
# setup nginx
	mkdir -p /etc/nginx/sites-enabled

    cat > /etc/nginx/php.conf <<END
location ~* \.(ico|css|js|gif|jpeg|jpg|png)(\?[0-9]+)?\$ {
        expires max;
        break;
}

location ~ .*\.php\$
{

        fastcgi_pass_request_body off;
        client_body_temp_path /tmp/client_body_temp;
        client_body_in_file_only clean;
        fastcgi_param REQUEST_BODY_FILE \$request_body_file;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
        fastcgi_index index.php;
        include /etc/nginx/fastcgi_params;

}
END
	cat > /etc/nginx/wp.conf <<END
location / {
	if (!-e \$request_filename) { 
    		rewrite ^(.+)\$ /index.php?q=\$1 last; 
	}
}
END
	cat > /etc/nginx/fastcgi_params <<END
fastcgi_param  QUERY_STRING       \$query_string;
fastcgi_param  REQUEST_METHOD     \$request_method;
fastcgi_param  CONTENT_TYPE       \$content_type;
fastcgi_param  CONTENT_LENGTH     \$content_length;

fastcgi_param   SCRIPT_FILENAME     \$request_filename;
fastcgi_param  SCRIPT_NAME        \$fastcgi_script_name;
fastcgi_param  REQUEST_URI        \$request_uri;
fastcgi_param  DOCUMENT_URI       \$document_uri;
fastcgi_param  DOCUMENT_ROOT      \$document_root;
fastcgi_param  SERVER_PROTOCOL    \$server_protocol;
fastcgi_param  HTTPS              \$https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    Apache/2.1.4;

fastcgi_param  REMOTE_ADDR        \$remote_addr;
fastcgi_param  REMOTE_PORT        \$remote_port;
fastcgi_param  SERVER_ADDR        \$server_addr;
fastcgi_param  SERVER_PORT        \$server_port;
fastcgi_param  SERVER_NAME        \$server_name;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
fastcgi_param  REDIRECT_STATUS    200;
END

	cat > /etc/nginx/nginx.conf <<END
user nobody;
worker_processes  1;
#worker_cpu_affinity 01 10 01 10 01 10 01 10;
 
error_log  /var/log/nginx/error_log crit;
pid        /var/run/nginx.pid;
worker_rlimit_nofile 65535;
events
{
	use epoll;
	worker_connections  4096;
}
http
{
#	include /etc/nginx/deny.iplist;
	include       /etc/nginx/mime.types;
	default_type  application/octet-stream;
	server_name_in_redirect off;
	server_names_hash_bucket_size 64;
	server_tokens off;
	client_header_buffer_size 4k;
	large_client_header_buffers 4 16k;
	client_max_body_size 8m;
	sendfile        on;
	tcp_nopush     on;
	keepalive_timeout 65;
	tcp_nodelay        off;
	client_body_timeout 10;
	client_header_timeout 10;
	send_timeout 60;
	output_buffers 1 32k;
	postpone_output 1460;
	fastcgi_connect_timeout 300;
	fastcgi_send_timeout 300;
	fastcgi_read_timeout 300;
	fastcgi_buffer_size 4k;
	fastcgi_buffers 8 4k;
	fastcgi_busy_buffers_size 8k;
	fastcgi_temp_file_write_size 8k;
	log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
'\$status \$body_bytes_sent "\$http_referer" '
'"\$http_user_agent" \$http_x_forwarded_for';
	gzip on;
	gzip_buffers     4 16k;
	gzip_http_version 1.0;
	gzip_comp_level 3;
	gzip_types       text/plain application/x-javascript text/css application/xml;
	include /etc/nginx/sites-enabled/*;
}
END
	cat >/etc/nginx/sites-enabled/default <<END
server {
        listen 80 default;
        index index.php index.htm index.html;
#    	autoindex on;
#      	autoindex_exact_size off;
#       autoindex_localtime on;
      	root /var/www;
		access_log /var/log/nginx/access.log main;
#		limit_rate_after 10m;
#    	limit_rate 512k;
#    	location ~ \.flv
#    	{
#     	 flv;
#    	}
		include php.conf;
}
END
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
	sleep 2s
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
	mysql -uroot mysql<temp.sql
	rm -rf ~/temp.sql
#	mysql -uroot -p"$passwd" <temp.sql
    chmod 600 ~/.my.cnf
	service mysqld restart

# setup complete
	service mysqld start
	service php-fpm start
	service nginx start
	chkconfig mysqld on
	chkconfig php-fpm on
	chkconfig nginx on
}

function install_vhost {
	if [ ! -d /home/www ];
        then
        mkdir /home/www
	fi
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` <hostname>"
    fi
	mkdir "/home/www/$1"
 	chown -R nginx "/home/www/$1"
	chmod -R 755 "/home/www/$1"
	wget -P "/home/www/$1" https://github.com/kwxiaozhu/shell/raw/master/tz.php

# Setting up Nginx 
    cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server {
	listen 80;
	server_name $1;
	index index.php index.htm index.html;
	root /home/www/$1;
	access_log /var/log/nginx/access_$1.log main;
	include php.conf;
}
END
    service nginx reload
}

function install_vsftpd {
	yum -y install vsftpd db4-utils
	service vsftpd stop
	mv /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak
	if [ ! -d /home/www ];
        then
        mkdir /home/www
	fi
	chown nobody:nobody -R /home/www
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
local_root=/home/www/
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

	 cat > /etc/yum.repos.d/nginx.repo <<END
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=0
enabled=1
END
	yum update -y
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
lnmp)
    install_lnmp
    ;;
system)
    remove_unneeded
    update_upgrade
    ;;
vhost)
    install_vhost $2
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
addnginx)
    sed -i s/'^worker_processes  [0-9];'/'worker_processes kwxiaozhu;'/g /etc/nginx/nginx.conf
	sed -i s/kwxiaozhu/$2/g /etc/nginx/nginx.conf
	service nginx restart
	;;
addfpm)
	sed -i  s/'^pm.max_children = [0-9]*'/'pm.max_children = kwxiaozhu'/ /etc/php-fpm.d/www.conf
	sed -i s/kwxiaozhu/$2/ /etc/php-fpm.d/www.conf
	service php-fpm restart
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
    for option in system lnmp vhost vsftpd ssh addnginx addfpm sshport
    do
        echo '  -' $option
    done
    ;;
esac
