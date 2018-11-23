#!/usr/local/bin/python3

# By: Ricardo Diaz
# Date: 20181123
# Python3
# Name: cisco_switch_pexpect_ver_1.05.py (pexpect_test_ver_1.16.py -- continuing off)
# Purpose: Logs into cisco switches/routers, executes show commands, takes the outputs of the show commands and writes to file (1 file per device).
#-------------------------------------------------------
# How to run script:
# python3.6 cisco_switch_pexpect_ver_1.04.py ip_file command_file CHICAGO135 backup /Users/rdiaz/Documents/bit_bucket/netchil33t/rdiaz/dev/
# python3.6 [python_script.py] [ipfile] [command_file] [SITE] [TYPE] [PATH]

# - 2 user input files: ip_file and command_file. (example below)
# - Credentials (username and password)
# - Directory path

#1: ip_file == file with list of ip addresses
#    Ricardo-Mac:dev rdiaz$ cat ip_file
#    172.16.26.3  usjol-c871-rtr-01
#    172.16.26.4  usjol-c1841-rtr-02
#
#2. command_file == file with show commands you'll like to execute on all IPs on the ip_file.
#    Ricardo-Mac:dev rdiaz$ cat command_file
#    show run | in hostname
#    show clock
#    show ip interface brief
#    show inventory
#-------------------------------------------------------

# Referance:
# https://pexpect.readthedocs.io/en/stable/
# http://pexpect.sourceforge.net/doc/
# https://stackoverflow.com/questions/31143811/pexpect-login-to-cisco-device-grab-just-the-hostname-from-the-config
# https://www.electricmonk.nl/log/2014/07/26/scripting-a-cisco-switch-with-python-and-expect/
# https://stackoverflow.com/questions/35585158/python-pexpect-regex-match-is-encased-in-b

# ~~~~~~~~~~
# Import modules
# ~~~~~~~~~~
import os
import sys
import pexpect
import time
import datetime
import re
from getpass import getpass

# ~~~~~~~~~~
# Testing area
# ~~~~~~~~~~
'''
#print ('TESTING NOW')

print (sys.argv[1])


try:
    print (x)
except:
    print ('An error occured')

sys.exit(1)
'''

# ~~~~~~~~~~
# Define regex
# ~~~~~~~~~~
re_hostname = (r"hostname\s([\w|\d|-]+)") #will be regex following line | 'show run | in hostname==========hostname usjol-fw-srx-lab-01==========usjol-fw-srx-lab-01'
re_ip = (r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")

# ~~~~~~~~~~
# Define variables
# ~~~~~~~~~~
testline = ('-' * 15 + 'TESTING LINE' + '-' * 15) # --------------TESTING LINE---------------
space01 = ('=' * 15 + '\n')
space02 = ('\n' + '=' * 15 + '\n')
end_of_line = ('-' * 5 + 'end_of_line' + '-' * 5 + '\n')
ssh_newkey = ('Are you sure you want to continue connecting')
diffie_hellman_group1_sha1 = ('no matching key exchange method found. Their offer: diffie-hellman-group1-sha1')
ssh_key_fail = ('Host key verification failed.')
#enable = ('your enable password')
hashtag = ('#')
greaterthan = ('>')
left_parenthese = ('(')



# ~~~~~~~~~~
# Define functions
# ~~~~~~~~~~
def def_test():
    print ('testing function')

def def_write_filenames_to_file():
    os.chdir(path)
    os.system("ls > qfilenames.txt")

def def_change_directory():
    os.chdir(path)

def def_wrong_creds():
    global var_next_device
    var_next_device = (0)
    print ('***ERROR: Bad credentials for IP [' + ip_address + ']***')
    while True:
        var_next_device = (1)
        break

def def_create_dir_for_backup_files():
    global path
    var_date_yyyymmdd = datetime.datetime.now().strftime("_%Y%m%d") #time into a variable

    print ("Going to create a new directory but first user will need to enter full path in which the directory will be created")

    print ("\nCURRENT DIRECTORY:\n" + space01)
    print (os.system("pwd"))
    print (space01 + "\n")

    #ui_path = ('/Users/rdiaz/Documents/bit_bucket/netchil33t/rdiaz/dev/') # TESTING
    #ui_path = input('Enter full path: ') # UNCOMMENT WHEN DONE TESTING
    ui_path = sys.argv[5]

    path = ui_path + ui_site + "_backup" + var_date_yyyymmdd
    try:
        os.mkdir(path) # creates directory. User will enter path in which new dir will be created
        #os.chdir(path) # change directory that was just created
    except OSError:
        print ("FAILED: Creation of the directory %s failed" % path)
    else:
        print ("Successfully created the directory %s " % path)

# Function will open user input (ui) ip list file and add IP addresses to a list/array [ip_file_ips]
def def_open_ip_file():
    global ip_file_ips
    ip_file_ips = [] #Create empty directory, will append ip addresses once regex
    with open(ui_ip_filename, 'r') as var_open_ui_ip_filename: # opens file, reads file and store in variable (var_open_ui_ip_filename)
        var_open_ui_ip_filename = [line.rstrip('\n') for line in var_open_ui_ip_filename]
        # Reads through every line in file var_open_ui_ip_filename, regex out IP adderss and appends that to the new list (ip_file_ips)
        for line in var_open_ui_ip_filename:
            re_match_ip = re.search(re_ip, line)
            var_re_match_ip_g0 = re_match_ip.group(0)
            var_re_match_ip_g1 = re_match_ip.group(1)
            ip_file_ips.append(var_re_match_ip_g0)

# Function will open user input (ui) command list file
def def_open_command_file():
    global var_open_ui_command_filename
    with open(ui_command_filename, 'r') as var_open_ui_command_filename: # opens file, reads file and store in variable
        var_open_ui_command_filename = [line.rstrip('\n') for line in var_open_ui_command_filename]

def def_verify_password():
    ssh_expect_list = child.expect([pexpect.TIMEOUT, ssh_newkey, diffie_hellman_group1_sha1, ssh_key_fail, '[Pp]assword: ', '#'])
    if ssh_expect_list == 5: # expecting '#'
        print ('***[' + ip_address + '] Loging into IP***')
    if ssh_expect_list == 4: # expecting 'Password', meaning that the password was incorrect
        def_wrong_creds()

# TESTING FUNCTION
################################
def def_expect_cisco_command_mode():
    # Expecting one of the cisco command modes
    cisco_command_mode = child.expect([privileged_EXEC, '\(#'])
    #print (testline) # TESTING

    #sys.exit(1) # TESTING
    if cisco_command_mode == 0: # privileged_EXEC, Router01#
        print ('***[' + ip_address + '] in privileged_EXEC mode: [' + privileged_EXEC + ']')
    if cisco_command_mode == 1: #global_configuration, Router01(config)#
        print ('***[' + ip_address + '] in global_configuration mode: [' + global_configuration2 + ']')


    '''
    if cisco_command_mode == 0: #user_EXEC, Router01>
        print ('***[' + ip_address + '] in user_EXEC mode: [' + user_EXEC + ']')
    if cisco_command_mode == 1: #privileged_EXEC, Router01#
        print ('***[' + ip_address + '] in privileged_EXEC mode: [' + privileged_EXEC + ']')
    if cisco_command_mode == 2: #global_configuration, Router01(config)#
        print ('***[' + ip_address + '] in global_configuration mode: [' + global_configuration + ']')
    '''
################################

# Function to send show command(s) once logged into device
def def_send_cli_command():
    def_change_directory() #UNCOMMENT WHEN DONE TESTING

    child.sendline(cli_command)
    #print (cli_command)
    #child.expect('#') # run into issue if the output has "#" in the first line (example is [show inventory])
    # EXAMPLE BELOW
    '''
    usjol-c870-rtr-lab-01#show inventory
    NAME: "871", DESCR: "871 chassis, Hw Serial#: FHK123222TX, Hw Revision: 0x300"
    PID: CISCO871-K9         , VID: V05 , SN: FHK123222TX


    usjol-c870-rtr-lab-01#
    '''
    #child.expect(var_hostname) # Was expecing 'HOSTNAME01#' originally. would want to improve code. to be removed
    # function that expects all 3 types of cisco command modes ('>', '#', '(')
    #def_expect_cisco_command_mode() # TESTING FUNCTION

    #cisco_command_mode = child.expect([privileged_EXEC, '\)#']) # Expect either HOSTNAME# or ')#'
    #cisco_command_mode = child.expect([privileged_EXEC, var_re_match_hostname_g1 + '.*#', var_re_match_hostname_g1 + ' '])

    # CISCO IOS COMMAND MODES
    # -------------------------
    global_config_mode = (var_re_match_hostname_g1 + '\(config\)#') # cisco_command_mode:1
    interface_config_mode = (var_re_match_hostname_g1 + '\(config-if\)#') # cisco_command_mode:2
    interface_range_config_mode = (var_re_match_hostname_g1 + '\(config-if-range\)#') # cisco_command_mode:3
    vlan_config_mode = (var_re_match_hostname_g1 + '\(config-vlan\)#') # cisco_command_mode:4
    router_config_mode = (var_re_match_hostname_g1 + '\(config-router\)#') # cisco_command_mode:5
    line_config_mode = (var_re_match_hostname_g1 + '\(config-line\)#') # cisco_command_mode:6
    acl_std_mode = (var_re_match_hostname_g1 + '\(config-std-nacl\)#') # cisco_command_mode:7
    acl_ext_mode = (var_re_match_hostname_g1 + '\(config-ext-nacl\)#') # cisco_command_mode:8
    #catch_all = (var_re_match_hostname_g1 + '.*#') # CATCHES SHOW VERSION, SHOW RUN. NOT GOOD
    # -------------------------

    # Expect one of the cisco IOS command modes
    cisco_command_mode = child.expect([privileged_EXEC, global_config_mode, interface_config_mode, interface_range_config_mode, vlan_config_mode, router_config_mode, line_config_mode, acl_std_mode, acl_ext_mode])

    output =  child.before
    output = output.decode("utf-8")

    #print (output) # prints out all output of the show commands
    with open (ui_site + '_' + ui_describe_file + '_' + var_re_match_hostname_g1 + '_' + ip_address + '.txt', 'a') as var_write_to_file:
            var_write_to_file.write(space01 + 'COMMAND: ' + cli_command + space02)
            print ('***[' + ip_address + '] running [' + cli_command + ']')
            var_write_to_file.write(output)
            var_write_to_file.write(end_of_line)
            var_write_to_file.write('\n')

# Function to login into devices regardless if devices are not reachable, ssh keys, password
def def_ssh_to_host():
    global child
    global var_next_device
    var_next_device = (0) # 0 means good. If value is later on changed to 1, will continue with next IP in list

    ssh = 'ssh ' + (username) + '@' +(ip_address)
    ssh_dh = 'ssh -l ' + (username) + ' -oHostKeyAlgorithms=+ssh-dss -oKexAlgorithms=+diffie-hellman-group1-sha1 ' + (ip_address)

    child = pexpect.spawn(ssh) #'ssh ' + (username) + '@' +(ip_address)

    i = child.expect([pexpect.TIMEOUT, ssh_newkey, diffie_hellman_group1_sha1, ssh_key_fail, '[Pp]assword: ', '#']) # list/array, count starts from 0, 1, 2, 3
    #0 - pexpect.TIMEOUT
    #1 - ssh_newkey
    #2 - diffie_hellman_group1_sha1
    #3 - ssh_key_fail
    #4 - [Pp]assword
    #5 - #

    if i == 0: # Timeout
        print('***[' + ip_address + '] ---ERROR--- Unable to ssh due to TIMEOUT***')
        #print(child.before, child.after)
        while i == 0:
            var_next_device = (1)
            break

    if i == 1: # SSH does NOT have the public key. Just accept it.
        print ('***[' + ip_address + '] Accepting public SSH key***')
        child.sendline ('yes')
        child.expect ('[Pp]assword: ')
        child.sendline(password)
        def_verify_password()

    if i == 2: # diffie_hellman_group1_sha1
        print ('***[' + ip_address + '] --WARNING-- No matching key exchange method found. Their offer: diffie-hellman-group1-sha1***')
        child = pexpect.spawn(ssh_dh) #'ssh -l '+(username)+' -oHostKeyAlgorithms=+ssh-dss -oKexAlgorithms=+diffie-hellman-group1-sha1 '+(ip_address)

        i2 = child.expect([pexpect.TIMEOUT, ssh_newkey, diffie_hellman_group1_sha1, ssh_key_fail, '[Pp]assword: ', '#'])
        if i2 == 4: # expecting 'PASSWORD'
            # Run if the the local host has the public key
            child.sendline(password)
            def_verify_password()
        elif i2 == 1: # SSH does not have the public key. Just accept it.
            print ('***[' + ip_address + '] Accepting public SSH key***')
            child.sendline ('yes')
            child.expect ('[Pp]assword: ')
            child.sendline(password)
            def_verify_password()

    # NEED TO ADDRESS THE BELOW.
    if i == 3: # Host key verification failed.
        print ('i == 3')
        print (space01 + 'Host key verification fail for [' + ip_address + ']')
        while i == 3:
            var_next_device = (1)
            break

    if i == 4: # Expecting '[Pp]assword: '
        print ('***['+ip_address+ '] Already have SSH keys')
        child.sendline(password)
        def_verify_password()

# Main function
def def_main():
    global child
    global cli_command
    #global var_hostname # to be retire
    global user_EXEC
    global privileged_EXEC
    global global_configuration
    global global_configuration2 # TESTING
    global var_re_match_hostname_g1

    # 1.
    # Function to login into devices regardless if devices are not reachable, ssh keys, password
    def_ssh_to_host()
    #print (testline)
    #print (var_next_device) #TESTING

    # 2. If there are issues ssh into device (timeout, not online or host key verification failed)
    if var_next_device == 1:
        print ('***[' + ip_address + '] Unable to login. Moving on to next device/ip in the list/file.***')
        while var_next_device == 1:
            break

    # 3. Once logged into the device
    if var_next_device == 0:
        # Get hostname of the switch/router
        child.sendline('show run | in hostname')
        child.expect('#')
        byte_hostname = child.before # b'show run | in hostname\r\nhostname usjol-c870-rtr-lab-01\r\nusjol-c870-rtr-lab-01'
        #print (byte_hostname) # TEST prints b'show run | in hostname\r\nhostname usjol-c870-rtr-lab-01\r\nusjol-c870-rtr-lab-01'

        str_hostname = byte_hostname.decode('utf-8') # decoding bytes to string
        #print (str_hostname) # TEST prints the string as well as newlines \n and carriage \r (dont want this)
        '''
        show run | in hostname
        hostname usjol-c870-rtr-lab-01
        usjol-c870-rtr-lab-01
        '''
        replace_str_hostname = (str_hostname.replace('\r', '=====').replace('\n', '====='))
        #print (replace_str_hostname) # show run | in hostname==========hostname usjol-c870-rtr-lab-01==========usjol-c870-rtr-lab-01

        # Regex for hostname (group 1)
        re_match_hostname = re.search(re_hostname, replace_str_hostname)
        #var_re_match_hostname_g0 = re_match_hostname.group(0) # prints hostname usjol-c870-rtr-lab-01
        var_re_match_hostname_g1 = re_match_hostname.group(1) # prints usjol-c870-rtr-lab-01

        #var_hostname = (var_re_match_hostname_g1 + hashtag)
        #print (var_hostname) # usjol-c870-rtr-lab-01#

        # Setting up variables to expect any type of cisco command mode
        #user_EXEC = (var_re_match_hostname_g1 + greaterthan) # prints, Router01>
        privileged_EXEC = (var_re_match_hostname_g1 + hashtag) # prints, Router01#
        #global_configuration = (var_re_match_hostname_g1 + left_parenthese) # prints, Router01(
        #global_configuration2 = (var_re_match_hostname_g1 + '(config)#') # TESTING

        # FOR loop: for every show command found in file (var_open_ui_command_filename), call the FUNCTION [def_send_cli_command()]

        for cli_command in var_open_ui_command_filename:
            def_send_cli_command()


# ~~~~~~~~~~
# Start program here
# User input
# ~~~~~~~~~~

'''
# Entry point for program
if __name__ == '__main__':
    # Retrieve command line input
    try:
        ui_ip_filename =

python3.6 cisco_switch_pexpect_ver_1.03.py ip_file command_file site_here cdp_neigh
'''

ui_ip_filename = sys.argv[1]
#ui_ip_filename = input('Enter IP filename: ')
#ui_ip_filename = ('ip_file') # TESTING

ui_command_filename = sys.argv[2]
#ui_command_filename = input('Enter command filename: ')
#ui_command_filename = ('command_file') # TESTING

try:
    ui_site = sys.argv[3]
except IndexError:
    print ('Quiting program now... You forgot to enter a SITE NAME.')
    sys.exit(1)

try:
    ui_describe_file = sys.argv[4]
except IndexError:
    print ('Quiting program now... You forgot to enter TYPE OF FILE.')
    sys.exit(1)
#print ('Example: backup|interfaces|cdp_neighbors')
#ui_describe_file = input('Describe type of file: ')
#ui_describe_file = ("qqq") # TESTINGß

username = input('Enter username: ')
#username = ('cisco') # TESTING

password = getpass()
#password = ('cisco') # TESTING

# ~~~~~~~~~~
# Call functions
# ~~~~~~~~~~
def_open_ip_file()
def_open_command_file()
def_create_dir_for_backup_files()

for ip_address in ip_file_ips:
    def_main()


# ~~~~~~~~~~
# Error messages
# ~~~~~~~~~~
