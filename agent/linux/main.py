import time
import subprocess
import json
import os
import sys

import hids_func

# aller le répertoire où se trouve le script
os.chdir(os.path.dirname(os.path.abspath(__file__)))

API_KEY = open("conf/api_key",'r').read().replace("\n", "")
CONF_FILE_TO_MONITORE = "conf/files_to_monitore.lst"
OFFSET_FILE_START_PATH = "save/offset_"
HOSTNAME = open("conf/hostname.conf",'r').read().replace("\n", "")

def read_new_lines(file_path, offset_file):
    # offset = c'est le dernière octet lu

    # on récupère l'offset si il existe
    try:
        with open(offset_file, 'r') as offset_save:
            old_offset = int(offset_save.read())
    except:
        old_offset = 0 # si c'est la première fois c'est 0

    new_lines = []
    with open(file_path, 'r') as log_file:
        log_file.seek(old_offset) # on va à l'offset retenu
        new_lines = log_file.readlines() # on lis le contenu du fichier

        new_offset = log_file.tell() # on récupère l'offset ou on est après lecture

    with open(offset_file, 'w') as offset_save:
        offset_save.write(str(new_offset))

    return new_lines

def send_to_bdd(log):
    data = json.dumps({"apikey": API_KEY, "hostname": HOSTNAME, "log": log,})
    subprocess.run(["curl", "-X", "POST", "http://IP_INDEXER:8080", "-d", f"apikey={API_KEY}&hostname={HOSTNAME}&log={log}"])

def main():
    file_to_monitore = open(CONF_FILE_TO_MONITORE,'r').readlines()

    for log_file in file_to_monitore:
        log_file = log_file.replace("\n", "")
        offset_file_path = OFFSET_FILE_START_PATH + log_file.split("/")[-1]
        new_lines = read_new_lines(log_file, offset_file_path)
        for log in new_lines:
            send_to_bdd(log)

if __name__ == '__main__':
    hids_func.main()
    main()
