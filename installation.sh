#!/bin/bash

echo "default ui password is : defaultnotsecurepwd"
echo "change it after first use (press enter to confirm)"
read ok

echo "root mdp for the bdd :"
read rootpwd
sed -i "s/changeme_rootpwd/$rootpwd/g" infra/docker-compose.yml

echo "MYSQL_USER :"
read MYSQL_USER
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/docker-compose.yml
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/indexer/index.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/generate_api_key.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/index.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/auth.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/changepasswd.php

echo "MYSQL_PASSWORD :"
read MYSQL_PASSWORD
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/docker-compose.yml
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/indexer/index.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/generate_api_key.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/index.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/auth.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/changepasswd.php

# The JWT secret key is currently the MySql Root password, fixe that later
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/jwt.php

# Generate the self signed ssl key
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout infra/localhost.key -out infra/localhost.crt -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=localhost"

echo "bdd : localhost:3306";
echo "phpmyadmin : localhost:7777 (for debug)";
echo "indexer : localhost:8080";
echo "user interface : localhost:80";

# github delete the empty folder so i recreate it
mkdir agent/linux/save

zip -r agent_linux.zip agent/linux
mv agent_linux.zip infra/ui

zip -r agent_windows.zip agent/windows
mv agent_windows.zip infra/ui

docker compose -f infra/docker-compose.yml up
