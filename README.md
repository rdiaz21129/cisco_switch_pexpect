# Purpose: 
Logs into cisco switches/routers, executes show commands/configurations, takes the outputs of the show commands and writes (output) to file (1 file per device).

# How to run python script (version 1.05) <br />
	python3 <python_script.py> <ip_file> <command_file> <SITE_NAME> <purpose> <dump directory path>
	python3.7 cisco_switch_pexpect_ver_1.05.py ip_file command_file CHICAGO135 backup /home/rdiaz/config_backups/chicago135/backups/

# crontab -e
#[CHICAGO 135] Run backup python script for CHICAGO 135 every week on Thursday at 07:25am CST<br />
	25 7 * * 4 rm /home/rdiaz/.ssh/known_hosts; cd /home/rdiaz/config_backups/chicago135; ./cisco_switch_pexpect_ver_1.04.py ip_file command_file CHICAGO135 backup /home/rdiaz/config_backups/chicago135/backups/
