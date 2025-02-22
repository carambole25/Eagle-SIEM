"""
l'objectif est d'obtenir une sorte de status actuel du systeme
de le comparer avec l'anciens
d'update la sauvegarde du status
de sauvegarder les changements dans un fichier de log
fichier de log qui sera placé logiquement dans file_to_monitore.lst
"""
import os

CONF_CMD_TO_RUN = "conf/cmd_to_run.lst"

def load_conf(path):
    return [cmd.replace("\n", "") for cmd in open(path, "r").readlines()]

def run_cmd(cmd_list):
    date = "jesuisladate"
    for cmd in cmd_list:
        cmd = cmd + f" > save/{date}_{cmd.replace(' ', '_').replace('/', '_')}.log"
        os.system(cmd)

def main():
    cmd_list = load_conf(CONF_CMD_TO_RUN)
    run_cmd(cmd_list)

main()