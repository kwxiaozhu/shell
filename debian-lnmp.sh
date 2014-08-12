#!/bin/bash
function check_sanity 
{
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

function die
{
		echo "ERROR: $1" > /dev/null 1>&2
		exit 1
}

get_char()
{
		SAVEDSTTY=`stty -g`
		stty -echo
		stty cbreak
		dd if=/dev/tty bs=1 count=1 2> /dev/null
		stty -raw
		stty echo
		stty $SAVEDSTTY
}

function get_password() 
{
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

function install_lnmp() 
{
		echo "Press any key to start install lnmp..."
		char=`get_char`
		DEBIAN_FRONTEND=noninteractive apt-get -q -y install exim4 bsd-mailx mysql-server  nginx php5-fpm php5-curl php5-gd php5-sqlite php5-mysql
		invoke-rc.d mysql stop
		invoke-rc.d exim4 stop
		invoke-rc.d php5-fpm stop
		invoke-rc.d nginx stop
		echo "setup php5-fpm ......"
		if [ ! -d /var/www ];then
				mkdir /var/www
		fi
		chown www-data:www-data /var/www
		wget -q -P "/var/www/" https://github.com/kwxiaozhu/shell/raw/master/tz.php
		cp /etc/php5/fpm/pool.d/www.conf /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'listen = 127.0.0.1:9000'/'listen = \/var\/run\/php5-fpm.sock'/ /etc/php5/fpm/pool.d/www-data.conf
		#	sed -i  s/'pm = dynamic'/'pm = static'/ /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'^pm.max_children = [0-9]*'/'pm.max_children = 2'/ /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'^pm.start_servers = [0-9]*'/'pm.start_servers = 1'/ /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'^pm.min_spare_servers = [0-9]*'/'pm.min_spare_servers = 1'/ /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'^pm.max_spare_servers = [0-9]*'/'pm.max_spare_servers = 2'/ /etc/php5/fpm/pool.d/www-data.conf
		#	sed -i  s/'user = apache'/'user = www-data'/ /etc/php5/fpm/pool.d/www-data.conf
		#	sed -i  s/'group = apache'/'group = www-data'/ /etc/php5/fpm/pool.d/www-data.conf
		sed -i  s/'memory_limit = 128M'/'memory_limit = 64M'/ /etc/php5/fpm/php.ini
		sed -i  s/'short_open_tag = Off'/'short_open_tag = On'/ /etc/php5/fpm/php.ini
		sed -i  s/'upload_max_filesize = 2M'/'upload_max_filesize = 8M'/ /etc/php5/fpm/php.ini

		echo "setup nginx ......"
		if [ ! -d /etc/nginx/sites-enabled ];then
				mkdir /etc/nginx/sites-enabled
		fi
		cat > /etc/nginx/common.conf <<END
# Global restrictions configuration file.
# Designed to be included in any server {} block.</p>
location = /favicon.ico {
	log_not_found off;
	access_log off;
}
location = /robots.txt {
	allow all;
	log_not_found off;
	access_log off;
}
# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
location ~ /\. {
	deny all;
	access_log off;
	log_not_found off;
}
location ~* \.(ico|css|js|gif|jpeg|jpg|png)(\?[0-9]+)?$ {
	expires max;
	break;
}
END
cat > /etc/nginx/wp.conf <<END
location / {
	# This is cool because no php is touched for static content. 
	# include the "?$args" part so non-default permalinks doesn't 
	# break when using query string
	try_files \$uri \$uri/ /index.php?\$args; 
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

#fastcgi_pass_request_body off;
#client_body_temp_path /tmp/client_body_temp;
#client_body_in_file_only clean;
#fastcgi_param REQUEST_BODY_FILE $request_body_file;
fastcgi_param  PHP_VALUE  "open_basedir=\$document_root:/tmp/:/proc/";
fastcgi_index index.php;
END

cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes  1;
#worker_cpu_affinity 01 10 01 10 01 10 01 10;

error_log  /var/log/nginx/error_log crit;
pid        /var/run/nginx.pid;
worker_rlimit_nofile 65535;
events
{
	use epoll;
	worker_connections  10000;
}
http
{
	#nclude /etc/nginx/deny.iplist;
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
	include /etc/nginx/sites-enabled/*.conf;
}
END
cat >/etc/nginx/sites-enabled/default.conf <<END
server {
	listen 80 default;
	index index.php index.htm index.html;
	root /var/www;
	access_log /var/log/nginx/access.log main;
	include common.conf;
	location ~ .*\.php$
	{
			include fastcgi_params;
			fastcgi_pass unix:/var/run/php5-fpm.sock;
	}
	
	#    	autoindex on;
	#      	autoindex_exact_size off;
	#       autoindex_localtime on;
	#		limit_rate_after 10m;
	#    	limit_rate 512k;
}
END
echo "setup mysql ......"
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

cat > ~/temp.sql <<END
delete from user where user='' or password='';
flush privileges;
END
mysql -uroot -p"$passwd" mysql<temp.sql
rm -rf ~/temp.sql
chmod 600 ~/.my.cnf
invoke-rc.d mysql restart

echo "setup exim4 server ......"
invoke-rc.d exim4 stop
if [ -f /etc/exim4/update-exim4.conf.conf ]
then
		sed -i "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" /etc/exim4/update-exim4.conf.conf
		sed -i "s/dc_local_interfaces='127.0.0.1 ; ::1'/dc_local_interfaces='127.0.0.1'/" /etc/exim4/update-exim4.conf.conf
		rm -rf /var/log/exim4/paniclog
fi
# setup complete
apt-get clean
invoke-rc.d mysql restart
invoke-rc.d exim4 restart
invoke-rc.d php5-fpm start
invoke-rc.d nginx start
echo "========================"
echo "lnmp installed complete!"
echo "default webroot /var/www"
echo "default webuser www-data"
echo "default mysql root password is stored in ~/.my.cnf"
echo "please visit http://YOUR_IP/tz.php"
echo "========================"
}
function install_vhost 
{
		domain="www.kwxiaozhu.com"
		echo "Please input domain:"
		read -p "(Default domain: www.kwxiaozhu.com):" domain
		if [ "$domain" = "" ]; then
				domain="www.kwxiaozhu.com"
		fi
		grep "$domain" /etc/nginx/sites-enabled/* >/dev/null 2>&1
		if [ $? -eq 0 ] ; then
				echo "==========================="
				echo "$domain is exist!"
				echo "===========================" 
				exit 0
		else
				echo "==========================="
				echo "domain=$domain"
				echo "==========================="	
		fi

		echo -n "Please input website username:"
		read -p "(Default username: www):" username
		grep "$username" /etc/passwd > /dev/null 2>&1
		if [ $? -eq 0 ] ; then
				user_exist='y'
				echo "==========================="
				echo "$username is exist!"
				echo "==========================="
				echo "Do you want to add a website use this username? (Y/n)"
				read add_a_site
				if [ "$add_a_site" == 'n' ]; then
						exit 0	
				fi
		else
				echo "==========================="
				echo "username=$username"
				echo "===========================" 
		fi

		echo ""
		echo "Press any key to start create virtul host..."
		char=`get_char`

		echo "Create Virtual Host User......"
		if [ "$user_exist" !== 'y' ]; then 
				useradd -s /bin/false -d /home/$username $username
		fi
		echo "Create Virtul Host directory......"
		mkdir -p /home/$username/{logs,$domain,tmp,sessions}

		echo "set permissions of Virtual Host directory......"
		chmod 711 /home
		chmod 711 "/home/$username"
		if [ "$user_exist" != 'y' ]; then 
				chown -R $username:$username "/home/$username"
		fi
		chown -R $username:www-data  /home/$username/$domain
		chmod 710 /home/$username/$domain
		chmod 700 /home/$username/logs

		wget -q -P "/home/$username/$domain" https://github.com/kwxiaozhu/shell/raw/master/tz.php

		echo "Create php5-fpm config file......"
		if [ ! -f "/etc/php5/fpm/pool.d/$username.conf" ]; then
				cat > "/etc/php5/fpm/pool.d/$username.conf" <<END
[$username]
listen = /var/run/php5-fpm-$username.sock
user = $username
group = $username
pm = dynamic
pm.max_children = 3
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 10000
slowlog = /home/$username/logs/www-slow.log
env[TMP] = /home/$username/tmp
env[TMPDIR] = /home/$username/tmp
env[TEMP] = /home/$username/tmp
php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f noreply@$domain
php_flag[display_errors] = off
php_admin_value[memory_limit] = 64M
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = /home/$username/sessions
php_admin_value[session.cookie_path] = /home/$username/sessions
php_admin_value[upload_tmp_dir] = /home/$username/tmp
php_admin_value[disable_functions] = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,fsocket
END
		fi
		echo "Create nginx vhost config file......"
		if [ ! -f "/etc/nginx/sites-enabled/$username.conf" ]; then
				cat > "/etc/nginx/sites-enabled/$username.conf" <<END
server {
	listen 80;
	server_name $domain;
	index index.php index.htm index.html;
	root /home/$username/$domain;
	access_log /home/$username/logs/access_$domain.log main;
	error_log /home/$username/logs/error_$domain.log crit;
	include common.conf;
	location ~ .*\.php$
	{
		include fastcgi_params;
		fastcgi_pass unix:/var/run/php5-fpm-$username.sock;
	}
}
END
else
		cat >> "/etc/nginx/sites-enabled/$username.conf" <<END
server {
	listen 80;
	server_name $domain;
	index index.php index.htm index.html;
	root /home/$username/$domain;
	access_log /home/$username/logs/access_$domain.log main;
	error_log /home/$username/logs/error_$domain.log crit;
	include common.conf;
	location ~ .*\.php$
	{
		include fastcgi_params;
		fastcgi_pass unix:/var/run/php5-fpm-$username.sock;
	}
}
END
	fi
	service nginx reload
	service php-fpm reload
	echo "==========================="
	echo "Create Virtual Host Complete!"
	echo "site:		http://$domain "
	echo "webroot:	/home/$username/$domain"
	echo "webuser:	$username"
	echo "Please visit http://$domain/tz.php to check"
	echo "enjoy!"
	echo "==========================="
}

function install_vsftpd 
{
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

function remove_unneeded 
{
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

function update_upgrade 
{
		# Run through the apt-get update/upgrade first. This should be done before
		# we try to install any package

		echo "deb http://packages.dotdeb.org $(lsb_release -cs) all" | tee -a /etc/apt/sources.list
		echo "deb-src http://packages.dotdeb.org $(lsb_release -cs) all" | tee -a /etc/apt/sources.list
		wget -O - http://www.dotdeb.org/dotdeb.gpg | apt-key add -
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
