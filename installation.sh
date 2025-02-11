#!/bin/bash

echo "root mdp for the bdd :"
read rootpwd
sed -i "s/changeme_rootpwd/$rootpwd/g" infra/docker-compose.yml

echo "MYSQL_USER :"
read MYSQL_USER
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/docker-compose.yml
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/indexer/index.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/generate_api_key.php
sed -i "s/changeme_MYSQL_USER/$MYSQL_USER/g" infra/ui/index.php

echo "MYSQL_PASSWORD :"
read MYSQL_PASSWORD
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/docker-compose.yml
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/indexer/index.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/generate_api_key.php
sed -i "s/changeme_MYSQL_PASSWORD/$MYSQL_PASSWORD/g" infra/ui/index.php


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

sudo docker compose -f infra/docker-compose.yml up
