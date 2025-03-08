import os

CONF_CMD_TO_RUN = "conf/cmd_to_run.lst"

def load_conf(path):
    return [cmd.replace("\n", "") for cmd in open(path, "r").readlines()]

def run_cmd(cmd_list):
    for cmd in cmd_list:
        cmd_2 = f"bash -c 'diff <({cmd}) save/old_{cmd.replace(' ', '_').replace('/', '_')}.log &>/dev/null || echo \"changement detecté sur le resultat de la commande {cmd}\" >> eagle_hids.log'"
        os.system(cmd_2)
        cmd = cmd + f" > save/old_{cmd.replace(' ', '_').replace('/', '_')}.log"
        os.system(cmd)

def main():
    cmd_list = load_conf(CONF_CMD_TO_RUN)
    run_cmd(cmd_list)