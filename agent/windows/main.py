import os
from evtx import PyEvtxParser
import subprocess

script_dir = os.path.dirname(os.path.abspath(__file__))

api_key_path = os.path.join(script_dir, "conf", "api_key")
API_KEY = open(api_key_path, 'r').read().replace("\n", "")

hostname_path = os.path.join(script_dir, "conf", "hostname.conf")
HOSTNAME = open(hostname_path, 'r').read().replace("\n", "")

evtx_conf_path = os.path.join(script_dir, "conf", "evtx_srv.lst")
EVTX_CONF_PATH = evtx_conf_path

save_start_path = os.path.join(script_dir, "save", "cache_")
SAVE_START_PATH = save_start_path

def save_new_last_event_id(end_path, to_save):
    save = SAVE_START_PATH+end_path.split('\\')[-1]+".cache"
    save_file = open(save, "w")
    to_save = str(to_save)
    save_file.write(to_save)
    save_file.close()

def read_evtx(file, regex, save_event_id):
    parser = PyEvtxParser(f'{file}')
    last_event_id = save_event_id
    for record in parser.records():
        for re in regex:
            if re in record['data'] and record["event_record_id"] > save_event_id:
                print(f'Event Record ID: {record["event_record_id"]}')
                last_event_id = record["event_record_id"]
                log = str(record["timestamp"] + record['data'])
                subprocess.run(["curl", "-X", "POST", "http://IP_INDEXER:8080", "-d", f"apikey={API_KEY}&hostname={HOSTNAME}&log={log}"])
    return last_event_id

def read_save(end_path):
    save = SAVE_START_PATH+end_path.split('\\')[-1]+".cache"
    if not os.path.exists(save):
        last_event_id = 0
    else:
        last_event_id = int(open(save, "r").read().replace("\n", ""))

    return last_event_id

def read_conf(evtx_conf_path):
    lines = open(evtx_conf_path, "r").readlines()
    evxt_to_read = []
    for l in lines:
        l = l.split(' | ')
        path = l[0]
        regex = l[1].split(',')
        evxt_to_read.append([path, regex])
    return evxt_to_read

def main():
    conf = read_conf(EVTX_CONF_PATH)
    for c in conf:
        print(c)
        c.append(read_save(c[0])) # on rajoute le dernier event id lu si sauvegardé
        last_event_id = read_evtx(c[0], c[1], c[2])
        save_new_last_event_id(c[0], last_event_id)

if __name__ == '__main__':
    main()