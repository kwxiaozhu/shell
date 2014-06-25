#!/bin/bash
function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/debian_version ]
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
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_lnmp() {
	DEBIAN_FRONTEND=noninteractive apt-get -q -y install exim4 bsd-mailx mysql-server-5.1  nginx php5-fpm php5-curl php5-gd php5-sqlite php5-mysql
	invoke-rc.d mysql stop
	invoke-rc.d exim4 stop
	invoke-rc.d php5-fpm stop
	invoke-rc.d nginx stop
# setup php5
	mkdir -p /var/www
	wget -P "/var/www/" http://kwxiaozhu.googlecode.com/svn/tz.php
    chown www-data:www-data /var/www
	sed -i  "s/listen = 127.0.0.1:9000/listen = \/var\/run\/php5-fpm.sock/" /etc/php5/fpm/pool.d/www.conf
	sed -i  "s/pm = dynamic/pm = static/" /etc/php5/fpm/pool.d/www.conf
	sed -i  "s/^pm.max_children = [0-9]/pm.max_children = 3/" /etc/php5/fpm/pool.d/www.conf
	sed -i  "s/short_open_tag = Off/short_open_tag = On/" /etc/php5/fpm/php.ini
	sed -i  "s/upload_max_filesize = 2M/upload_max_filesize = 8M/" /etc/php5/fpm/php.ini
	
# setup nginx
    cat > /etc/nginx/conf.d/lowendbox.conf <<END
server_names_hash_bucket_size 64;
END

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
	cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes  2;
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
    cat > /etc/mysql/conf.d/lowendbox.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_size = 0
skip-innodb
END
	invoke-rc.d mysql start
    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin -uroot  password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
#	mysql -uroot -p"$passwd" <temp.sql
    chmod 600 ~/.my.cnf
	invoke-rc.d mysql restart
#setup exim4
	invoke-rc.d exim4 stop
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" /etc/exim4/update-exim4.conf.conf
		sed -i "s/dc_local_interfaces='127.0.0.1 ; ::1'/dc_local_interfaces='127.0.0.1'/" /etc/exim4/update-exim4.conf.conf
		cat >/etc/mailname <<END
kwxiaozhu.com
END
    fi
	rm -rf /var/log/exim4/paniclog

# setup complete
	apt-get clean
	invoke-rc.d mysql start
	invoke-rc.d exim4 start
	invoke-rc.d php5-fpm start
	invoke-rc.d nginx start
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
 	chown -R www-data "/home/www/$1"
	chmod -R 755 "/home/www/$1"
	wget -P "/home/www/$1" http://kwxiaozhu.googlecode.com/svn/tz.php

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
    invoke-rc.d nginx reload
}

function install_vsftpd {
	apt-get -y -q install vsftpd db4.8-util
	invoke-rc.d vsftpd stop
	mv /etc/vsftpd.conf /etc/vsftpd.conf.bak
	if [ ! -d /home/www ];
        then
        mkdir /home/www
	fi
	chown www-data:www-data -R /home/www
	cat >/etc/vsftpd.conf <<END
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
guest_username=www-data	
END
	cat >/etc/pam.d/vsftpd.vu <<END
auth	required	pam_userdb.so	db=/etc/vsftpd_login
account required	pam_userdb.so	db=/etc/vsftpd_login
END
	if [ ! -d /etc/vsftpd_user_conf ];
        then
        mkdir /etc/vsftpd_user_conf
	fi
	passwd=`get_password vsftpd`
	cat >~/.loguser.txt <<END
admin
$passwd
END
	db4.8_load -T -t hash -f ~/.loguser.txt /etc/vsftpd_login.db
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
	invoke-rc.d vsftpd start
	echo 'vsftpd setup complete!'
	echo 'admin account is admin,password is $passwd,home directory is /home/www'
	echo 'password file stored in .loguser.txt'
}

function remove_unneeded {
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
    fi
	DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge sendmail* apache2* samba* bind9* nscd
	invoke-rc.d saslauthd stop
	invoke-rc.d xinetd stop
	update-rc.d saslauthd disable
	update-rc.d xinetd disable
}

function update_upgrade {
    # Run through the apt-get update/upgrade first. This should be done before
    # we try to install any package

	 cat > "/etc/apt/sources.list" <<END
deb http://packages.dotdeb.org squeeze all
deb-src http://packages.dotdeb.org squeeze all

deb http://ftp.debian.org/debian squeeze main contrib non-free
deb http://security.debian.org squeeze/updates main contrib non-free
END
	wget http://www.dotdeb.org/dotdeb.gpg
	cat dotdeb.gpg | apt-key add -
	rm -rf dotdeb.gpg
    apt-get -q -y update
    apt-get -q -y upgrade
	apt-get clean
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
	invoke-rc.d nginx restart
	;;
addfpm)
	sed -i  s/'^pm.max_children = [0-9]'/'pm.max_children = kwxiaozhu'/ /etc/php5/fpm/pool.d/www.conf
	sed -i s/kwxiaozhu/$2/ /etc/php5/fpm/pool.d/www.conf
	invoke-rc.d php5-fpm restart
	;;
sshport)
	#sed -i  s/'Port 22'/'Port kwxiaozhu'/ /etc/ssh/sshd_config
	sed -i  s/'^Port [0-9]*'/'Port kwxiaozhu'/ /etc/ssh/sshd_config
	sed -i s/kwxiaozhu/$2/ /etc/ssh/sshd_config
	invoke-rc.d ssh restart
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
