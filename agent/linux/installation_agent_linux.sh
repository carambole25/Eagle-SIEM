#!/bin/bash

echo "Absolute path to the main.py file (example : /dir/example/main.py):"
read path_to_main

echo "IP of the indexer :"
read ip_indexer

sed -i "s|http://IP_INDEXER:8080|http://$ip_indexer:8080|" main.py

sudo chown root:root "$path_to_main"

sudo chmod +x "$path_to_main"

sudo bash -c "(sudo crontab -l 2>/dev/null; echo \"*/5 * * * * python3 $path_to_main\") | sudo crontab -"

echo "Ok !"
