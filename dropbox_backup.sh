#!/bin/bash
MYSQL_USER=root
MYSQL_PASS=123456
MAIL_TO=admin@w0w.me
WEB_DATA=/home/wwwroot #Backup Directory
DROPBOX_EMAIL=admin@w0w.me
DROPBOX_PASSWORD=123456
DROPBOX_DIRECTORY=/backup #Directory on Dropbox
MYSQL_BIN=/usr/local/bin/mysql
MYSQLDUMP_BIN=/usr/local/bin/mysqldump

DataBakName=Data_$(date +"%Y%m%d").tar.gz
WebBakName=Web_$(date +%Y%m%d).tar.gz
OldData=Data_$(date -d -5day +"%Y%m%d").tar.gz
OldWeb=Web_$(date -d -5day +"%Y%m%d").tar.gz
rm -rf /home/backup/Data_$(date -d -3day +"%Y%m%d").tar.gz /home/backup/Web_$(date -d -3day +"%Y%m%d").tar.gz
cd /home/backup
for db in `$MYSQL_BIN -u$MYSQL_USER -p$MYSQL_PASS -B -N -e 'SHOW DATABASES' | xargs`; do
    ($MYSQLDUMP_BIN -u$MYSQL_USER -p$MYSQL_PASS ${db} | gzip -9 - > ${db}.sql.gz)
done
tar zcf /home/backup/$DataBakName /home/backup/*.sql.gz
rm -rf /home/backup/*.sql.gz
echo "Subject:Backup" | mutt -a /home/backup/$DataBakName -s "Content:Database Backup" $MAIL_TO
tar zcf /home/backup/$WebBakName $WEB_DATA

dropbox()
{
#!/bin/bash#
# Dropbox Uploader Script
# by Andrea Fabrizi - andrea.fabrizi@gmail.com
# http://www.andreafabrizi.it/?dropbox_uploader
# edit by http://actgod.com

#DROPBOX ACCOUNT
LOGIN_EMAIL=$1
LOGIN_PASSWD=$2

LOGIN_URL="https://www.dropbox.com/login"
HOME_URL="https://www.dropbox.com/home"
UPLOAD_URL="https://dl-web.dropbox.com/upload"
COOKIE_FILE="/tmp/du_cookie_$RANDOM"
RESPONSE_FILE="/tmp/du_resp_$RANDOM"
BIN_DEPS="curl sed grep"


#Remove temporary files
function remove_temp_files
{
    rm -fr $COOKIE_FILE
    rm -fr $RESPONSE_FILE
}

#Extract token from the specified form
function get_token
{
    TOKEN=$(cat $1 | tr -s '\n' ' ' | sed -n -e 's/.*<form action="'$2'"[^>]*>\s*<input type="hidden" name="t" value="\([a-z 0-9]*\)".*/\1/p')
    echo $TOKEN      
}

#CHECK DEPENDENCIES
for i in $BIN_DEPS; do
    which $i > /dev/null
    if [ $? -ne 0 ]; then
        echo -e "Error: Required file could not be found: $i"
        remove_temp_files
        exit 1
    fi
done

#CHECK PARAMETERS
if [ $# != 4 ]; then
    echo -e "\n Usage:\t $0 [LOGIN_EMAIL] [LOGIN_PASSWD] [LOCAL_FILE] [REMOTE_FOLDER]\n"
    echo -e " Example:\n\t $0 i@actgod.com password /etc/myfile.txt /actgod\n"
    remove_temp_files
    exit 1
fi

#CHECK FILE
if [ ! -f $3 ]; then
    echo -e "Error: $1: No such file or directory"
    remove_temp_files
    exit 1
fi

UPLOAD_FILE=$3
DEST_FOLDER=$4


#LOAD LOGIN PAGE
echo -ne " > Loading Login Page..."
curl -s -i -o $RESPONSE_FILE "$LOGIN_URL"

if [ $? -ne 0 ]; then
    echo -e " Failed!"
    remove_temp_files
    exit 1
else
    echo -e " OK"
fi

#GET TOKEN
TOKEN=$(get_token "$RESPONSE_FILE" "\/login")
#echo -e " > Token = $TOKEN"
if [ "$TOKEN" == "" ]; then
    echo -e " Failed to get Authentication token!"
    remove_temp_files
    exit 1
fi

#LOGIN
echo -ne " > Login..."
curl -s -i -c $COOKIE_FILE -o $RESPONSE_FILE --data "login_email=$LOGIN_EMAIL&login_password=$LOGIN_PASSWD&t=$TOKEN" "$LOGIN_URL"
grep "location: /home" $RESPONSE_FILE > /dev/null

if [ $? -ne 0 ]; then
    echo -e " Failed!"
    remove_temp_files
    exit 1
else
    echo -e " OK"
fi

#LOAD HOME
echo -ne " > Loading Home..."
curl -s -i -b $COOKIE_FILE -o $RESPONSE_FILE "$HOME_URL"

if [ $? -ne 0 ]; then
    echo -e " Failed!"
    remove_temp_files
    exit 1
else
    echo -e " OK"
fi

#GET TOKEN
TOKEN=$(get_token "$RESPONSE_FILE" "https:\/\/dl-web.dropbox.com\/upload")
#echo -e " > Token = $TOKEN"
if [ "$TOKEN" == "" ]; then
    echo -e " Failed to get Upload token!"
    remove_temp_files
    exit 1
fi

#UPLOAD
echo -ne " > Uploading file..."
curl -s -i -b $COOKIE_FILE -o $RESPONSE_FILE -F "plain=yes" -F "dest=$DEST_FOLDER" -F "t=$TOKEN" -F "file=@$UPLOAD_FILE"  "$UPLOAD_URL"
grep "HTTP/1.1 302 FOUND" $RESPONSE_FILE > /dev/null

if [ $? -ne 0 ]; then
    echo -e " Failed!"
    remove_temp_files
    exit 1
else
    echo -e " OK"
fi

remove_temp_files
}

dropbox $DROPBOX_EMAIL $DROPBOX_PASSWORD /home/backup/$DataBakName $DROPBOX_DIRECTORY
dropbox $DROPBOX_EMAIL $DROPBOX_PASSWORD /home/backup/$WebBakName $DROPBOX_DIRECTORY