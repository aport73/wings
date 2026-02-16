systemctl stop wings
curl -L -o /usr/local/bin/wings https://github.com/aport73/wings/releases/latest/download/wings
chmod u+x /usr/local/bin/wings
systemctl restart wings