import psutil
from subprocess import call, Popen, PIPE, check_output, CalledProcessError, DEVNULL
import time
import os
from glob import glob

from manage_authorization_process import mainProcessAuthorizationExe

from manage_authorization_process import manageAuthorizationExecutionForUser
# import pwd


''' KERNEL PROCESS : 
https://unix.stackexchange.com/questions/411159/linux-is-it-possible-to-see-only-kernel-space-threads-process
ps --ppid 2 -p 2 -o uname,pid,ppid,cmd,cls
'''

# pop-up : 
# https://unix.stackexchange.com/questions/144924/how-can-i-create-a-message-box-from-the-command-line
# https://github.com/dunst-project/dunst


###n OU

# for proc in psutil.process_iter(['pid', 'name', 'username']):
#     print(proc.info)

## A VOIR  : psutil.wait_procs

# sudo apt install psmisc --> fuser

# p = psutil.Process(pids[-1])

# p = psutil.Process(9149)


# exe()
# cmdline()
# environ()
# parents()
# cwd()
# terminal()
# children(recursive=False)
# connections(kind="inet")
# suspend()
# resume()
# kill()



def getKernelProcess():
    # ps --ppid 2 -p 2 -o pid --no-header
    kernel_process = check_output(["ps", "--ppid", "2", "-p", "2", "-o", "pid", "--no-header"]).decode("latin").strip(' \t\n\r').split("\n")
    kernel_process.append(1)
    for i in range(len(kernel_process)):
        kernel_process[i] = int(kernel_process[i])
    print("kernel_process --> {}".format(kernel_process))
    return kernel_process

def removeItemInList(lst, item):
    try:
        return lst.remove(item)
    except Exception:
        return lst


def whereisPathForCommand(cmd):
    whereis_cmd = Popen(('whereis', "-b", cmd), stdout=PIPE, stderr=DEVNULL)
    reformate_whereis_cmd = check_output(('cut', '-d', ' ', '-f', '2'), stdin=whereis_cmd.stdout).decode("latin").strip()
    whereis_cmd.wait()
    # print("reformate_whereis_cmd --> {}".format(reformate_whereis_cmd))
    if reformate_whereis_cmd == "" or reformate_whereis_cmd[-1] == ":":
        return None
    return reformate_whereis_cmd

def getFileNotFoundInExe(pid):
    # print("\nEntrée dans la fonction getFileNotFoundInExe ---->\n")
    # pid = 563
    path_executable = []

    file_not_found_in_exe = psutil.Process(pid).as_dict()
    # print("file_not_found_in_exe -- {}".format(file_not_found_in_exe))
    path_exe = ""
    if file_not_found_in_exe["environ"] != None and ("PWD" in file_not_found_in_exe["environ"]):
        path_exe = file_not_found_in_exe["environ"]["PWD"]
        
    for cmd in file_not_found_in_exe["cmdline"]:
        if cmd == "" or cmd == "*" or cmd == "/" or ' ' in cmd or cmd[0] == "-":
            continue
        else:
            whereis_cmd = whereisPathForCommand(cmd)
            if whereis_cmd != None:
                path_executable.append(os.path.abspath(whereis_cmd))
                continue
        # else:
        #     try:
        #         output_which = check_output(["which", cmd], stderr=subprocess.STDERR).decode("latin").strip(' \t\n\r').split("\n")
        #         print("output_which --> {}".format(output_which))
        #         if len(output_which) > 0:
        #             for ow in output_which:
        #                 path_executable.append(os.path.abspath(ow))
        #             continue
        #     except Exception:
        #         pass
        
        try_list_path = [cmd, path_exe+"/"+cmd]
        for path_file in try_list_path:
            is_path_file_exists = os.path.isfile(path_file)
            

            path_folder_file = glob(path_file)
            # print("glob_file_folder --> {} -- {} -- {}".format(cmd, path_file, path_folder_file))
            if len(path_folder_file) > 0 and not os.path.isdir(path_file):
                # print("glob_file_folder --> {} -- {} -- {}".format(cmd, path_file, path_folder_file))
                for pff in path_folder_file:
                    path_executable.append(os.path.abspath(pff))
                break
            # else:
            #     whereis_cmd = whereisPathForCommand(cmd)
            #     if whereis_cmd != None:
            #         path_executable.append(os.path.abspath(whereis_cmd))
                


            # print("is_path_file_exists --> {} -- {}".format(is_path_file_exists, path_file))
            # if path_file[-1] != "*":
            #     if not is_path_file_exists:
            #         try:
            #             if path_exe == "":
            #                 continue
            #             ret_get_path = check_output("find {} -name {} 2> /dev/null".format(path_exe, path_file), shell=True).decode("latin").strip()
            #             print("ret_get_path ---> {} -- {} -- {}".format(ret_get_path, path_exe, path_file))
            #             if(len(ret_get_path) > 0):
            #                 print("ret_get_path ==> {}".format(ret_get_path))
            #                 path_executable.append(ret_get_path)
            #         except CalledProcessError as cpe:
            #             # print("[ERROR] {}".format(cpe))
            #             # print("path_exe : {} and cmd : {}".format(path_exe, path_file))
            #             continue
            #     else:
            #         path_executable.append(os.path.abspath(path_file))
    
    path_executable = removeItemInList(path_executable, ".")
    path_executable = removeItemInList(path_executable, "..")
    return path_executable


def getParentProcess(pid, list_parent_process):
    if(pid <= 1):
        return
    ret_pid = check_output(["ps", "-o", "ppid=", "-p", str(pid)]).decode("latin")
    # print("ret_resp --> {}".format(ret_pid))
    getParentProcess(int(ret_pid), list_parent_process)
    list_parent_process.append(int(ret_pid))

def getChildProcess(pid, list_child_process):
    if(pid <= 0):
        return
    ret_pid = check_output(["cat", "/proc/{}/task/{}/children".format(str(pid), str(pid))]).decode("latin").split(' ')[:-1]
    for rp in ret_pid:
        getChildProcess(int(rp), list_child_process)
        # print("ret_resp --> {}".format(ret_pid))
        list_child_process.append(int(rp))
    return


def getUidAndGidProcess(pid):
    list_uid_gid = check_output(["ps", "-o", "uid,gid", "-p", str(pid), "--no-header"]).decode("latin").strip().split('  ')
    return {"uid": list_uid_gid[0], "gid": list_uid_gid[1]}

'''
# test_pid = 11960
test_pid = 25404
# test_pid = 11091

getKernelProcess()

path_for_file_not_found = getFileNotFoundInExe(test_pid)
print("path_for_file_not_found --> {}".format(path_for_file_not_found))

json_uid_gid = getUidAndGidProcess(test_pid)
print("json_uid_gid --> {}".format(json_uid_gid))

list_parent_process = []
getParentProcess(test_pid, list_parent_process)
print("list_parent_process --> {}".format(list_parent_process))

list_child_process = []
getChildProcess(test_pid, list_child_process)
print("list_child_process --> {}".format(list_child_process))

print("Format process -->\nExe : {}\ncmdline: {}\nenviron : {}\nparents : {}\nchildren : {}\ncwd : {}\nterminal : {}\nOpenFile : {}\n".format(
    p.exe(),
    p.cmdline(),
    p.environ(),
    p.parents(),
    p.children(recursive=True),
    p.cwd(),
    p.terminal(),
    p.open_files()
))
'''

# exit(1)
################################################################################################

def findFiles(process_dict):
    result = []
    cmd_line = process_dict["cmdline"]
    print("cmd_line --> {}".format(cmd_line))
    for cl in cmd_line:
        try:
            print("cl --> {}".format(cl))
            # ret_resp = call(["pgrep", "-f", "-l", cl])
            ret_resp = check_output(["pgrep", "-f", "-l", cl]).decode("latin")
            print("ret_resp --> {}".format(ret_resp))
            sha256sum_ret = check_output(["sha256sum", "/proc/{}/exe".format(process_dict["pid"])]).decode("latin")
            print("sha256sum_ret ==> {}".format(sha256sum_ret))
        except e:
            print("TEST --> {}".format(e))




# Tout les pid qui ont pour parent 
# permettre à python3 d'être executé
# regarder les options pour voir si c'est des options ou fichiers
# utiliser la commande ps (plus facile et moins compliqué pour trouver les processus)

# print("status : {}\nUsername : {}\nCreateTime : {}\nOpen file : {}\nConnection : {}\nDict : {}".format(
#     p.status(),
#     p.username(),
#     p.create_time(),
#     p.open_files(),
#     p.connections(kind='tcp'),
#     p.as_dict()
# ))
# exit(1)

# pwdx 7844
'''
print("\nPid : {}\nPath : {}\nCommand Line : {}\nUsername : {}\nSSH CONNECTION ---\nLOGNAME : {}\nSsh : {}\n".format(
    process_dict["pid"],
    process_dict["cwd"],
    process_dict["cmdline"],
    process_dict["environ"]["USER"] if "USER" in process_dict["environ"] else None,
    process_dict["environ"]["LOGNAME"] if "LOGNAME" in process_dict["environ"] else None,
    process_dict["environ"]["SSH_CONNECTION"] if "SSH_CONNECTION" in process_dict["environ"] else None,
))
'''

# --> get ppid : ps axjf

# def findFiles(process_dict):
#     result = []
#     cmd_line = process_dict["cmdline"]
#     for cl in cmd_line:
#         try:
#             ret_resp = call(["pgrep", "-f -l", cl])
#             print("ret_resp --> {}".format(ret_resp))
#         except e:
#             print("TEST --> {}".format(e))


    # for root, dir, files in os.walk(search_path):
    #     if filename in files:
    #         result.append(os.path.join(root, filename))
    # return result

# --> get file in process : /proc/12611/cwd/
def suspend(pid):
    return call(["kill", "-STOP", str(pid)])

def resume(pid):
    return call(["kill", "-CONT", str(pid)])

def getFileFromProcess(process):
    print("[>] getFileFromProcess")
    process_dict = process.as_dict()
    pid = process_dict["pid"]
    ret_resp = call(["pwdx", str(pid)])
    print("ret_resp ==> {}".format(ret_resp))
    # findFiles



all_process_allow = psutil.pids()
# all_process_refuse = []

def initializeAllProcess():
    all_process_allow = psutil.pids()
    

def findNewProcess(all_process_allow, all_process):
    new_process = []
    for ap in all_process:
        if not (ap in all_process_allow):
            new_process.append(ap)
    return new_process



def manageKillProcess(pid):
    process_kill = psutil.Process(pid)
    if process_kill.is_running():
        print("Waiting for killing process {}".format(pid))
        process_kill.terminate()
        try:
            process_kill.wait(timeout=10)
        except psutil.TimeoutExpired as pte:
            if process_kill.is_running():
                print("Processus still running - {}".format(pte))
                process_kill.kill()

    '''
    if not (str(pid) in killed_process:
        killed_process[pid] = TIME_TO_SIGKILL
    
    process_kill = psutil.Process(pid)
    if process_kill.is_running():
        if killed_process[pid] >= 0:
            killed_process[pid] -= 1
        else:
            process_kill.kill()
    '''


# def manageProcessForUser(pid):
#     print("p.name : {}".format(p.as_dict()["name"]))
#     response_kill = ""
#     while(response_kill != "y" and response_kill != "n"):
#         response_kill = input("Voulez-vous tuer le process ou pas [y/n] ? ")
#         print("response_kill => {}".format(response_kill))
#         if(response_kill == 'y'):
#             print("Kill du processus {} en cours...".format(pid))
#             manageKillProcess(pid)
#         elif response_kill == "n":
#             ret_resp = call(["kill", "-CONT", str(pid)])
#             all_process_allow.append(pid)


# def handleProcess():
#     all_process = psutil.pids()
#     new_process = findNewProcess(all_process_allow, all_process)
#     print("new_process --> {}".format(new_process))
#     kernel_process = getKernelProcess()

#     # Faire le trie des process avec le fichier qu'on a mis en place (execution des process dans un chemin, certains process etc)
#     # peut-être en faisant du parallélisme.

#     # a = ['apple', 'carrot', 'lemon']
#     # b = ['pineapple', 'apple', 'tomato']
#     # new_list = [fruit for fruit in all_process if fruit not in b]

#     # manageAuthorizationExecutionForUser

#     # ASK_AGAIN && Non trouvé dans les fichiers
#     for np in new_process:
#         if not (np in kernel_process):
#             ret_resp = call(["kill", "-STOP", str(np)])
#             print("[>] Processus {} stoppé.".format(np))
#             manageProcessForUser(np)


def manageProcessForUser(pid):
    print("p.name : {}".format(p.as_dict()["name"]))
    response_kill = ""
    while(response_kill != "y" and response_kill != "n"):
        response_kill = input("Voulez-vous tuer le process ou pas [y/n] ? ")
        print("response_kill => {}".format(response_kill))
        if(response_kill == 'y'):
            print("Kill du processus {} en cours...".format(pid))
            manageKillProcess(pid)
        elif response_kill == "n":
            ret_resp = call(["kill", "-CONT", str(pid)])
            all_process_allow.append(pid)

# 'OLDPWD': '/home/gespenst/.vscode-server ou bien "ps_process.open_files()"
# Exe
# terminal (permet de trouver les terminals ouverts ou pas) ---> non

'''
Première execution --> mettre dans un tableau tous les processus pseudo-accepté.
A chaque fois qu'un processus apparait, on regarde s'il a été refusé, puis accepté.
Si il est en "ask_again" ou "None", on fait autre chose

Soit : On demande à l'utilisateur de valider/refuser le process
Soit : On le fait automatiquement (on refuse le process après XX secondes)
'''


# exit(1)

def handleProcess():
    all_process = psutil.pids()
    # new_process = findNewProcess(all_process_allow, all_process)
    # print("new_process --> {}".format(new_process))
    kernel_process = getKernelProcess()

    # Faire le trie des process avec le fichier qu'on a mis en place (execution des process dans un chemin, certains process etc)
    # peut-être en faisant du parallélisme.

    # a = ['apple', 'carrot', 'lemon']
    # b = ['pineapple', 'apple', 'tomato']
    new_process = [ap for ap in all_process if ap not in kernel_process]
    print("new_process --> {}".format(new_process))

    # manageAuthorizationExecutionForUser

    # ASK_AGAIN && Non trouvé dans les fichiers
    for np in new_process:
        try:
            ps_process = psutil.Process(np)
            print("\n\nFormat process -->\nExe : {}\ncmdline: {}\nenviron : {}\nparents : {}\nchildren : {}\ncwd : {}\nterminal : {}\nOpenFile : {}\n".format(
                ps_process.exe(),
                ps_process.cmdline(),
                ps_process.environ(),
                ps_process.parents(),
                ps_process.children(recursive=True),
                ps_process.cwd(),
                ps_process.terminal(),
                ps_process.open_files()
            ))
            sss = input("Pass : ")
            # ps_process.suspend()
            # print("[>] Processus {} stoppé.".format(np))
            # manageProcessForUser(np)
        except psutil.AccessDenied:
            continue

# getFileFromProcess(p)

# while(1):
#     print("handle_process")
#     handleProcess()
#     time.sleep(5)


def waitingForAction(pid, user, waiting_processes, DENY_AFTER_TIME_PASS=True):
    psutil_pid = psutil.Process(pid)
    waiting_processes[pid][0] -= 1
    psutil_pid.suspend()

    print("is_ruuning --> {}".format(psutil_pid.is_running()))

    if waiting_processes[pid][0] < 0: # DENY AFTER TIME PASSED (true or false) --- 
        if DENY_AFTER_TIME_PASS:
            main_process_authorization =  mainProcessAuthorizationExe(waiting_processes[pid][1], user, authorization_exe_decision="den")
            print("main_process_authorization ---> {}".format(main_process_authorization))
        waiting_processes.pop(pid)
        psutil_pid.kill()
    return waitingForAction
        



# https://unix.stackexchange.com/questions/2881/show-a-notification-across-all-running-x-displays
# notify-send hello
# ===> https://github.com/dunst-project/dunst

# cat /proc/PID/maps

# 5db3aea95763beeb659de22df605c78ccb21b8611e5674da49093595798b943b  /proc/7652/maps
# c36907e1aaa5db0a6866be9c3b3b2034cae11cd4afd27b684538efb14d5ee04d  /proc/7787/maps


# a333bea1ff24374b5ce3a229b583f709ed538d6822235f40ac210c70df65a22b  /proc/7787/exe
# a333bea1ff24374b5ce3a229b583f709ed538d6822235f40ac210c70df65a22b  /proc/7844/exe
# a333bea1ff24374b5ce3a229b583f709ed538d6822235f40ac210c70df65a22b  /proc/7846/exe

# ----> 7956

'''
    /proc/[pid]/stat/us --> ppid
    /proc/[pid]/task --> pour les threads
    /proc/[pid]/task/[tid]/children

    pgrep -f -l python3
'''


# [335, 538, 585]
'''
To see every process on the system using standard syntax:
          ps -e
          ps -ef
          ps -eF
          ps -ely

       To see every process on the system using BSD syntax:
          ps ax
          ps axu

       To print a process tree:
          ps -ejH
          ps axjf

       To get info about threads:
          ps -eLf
          ps axms

       To get security info:
          ps -eo euser,ruser,suser,fuser,f,comm,label
          ps axZ
          ps -eM

       To see every process running as root (real & effective ID) in user format:
          ps -U root -u root u

       To see every process with a user-defined format:
          ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,wchan:14,comm
          ps axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm
          ps -Ao pid,tt,user,fname,tmout,f,wchan

'''

# https://ostechnix.com/suspend-process-resume-later-linux/#:~:text=TL%3BDR,kill%20%2DCONT%20.
# kill -STOP
# kill -CONT

# pop

# manageProcessForUser(pids[-5])

# import tkinter as tk
# racine = tk.Tk()
# label = tk.Label(racine, text="J'adore Python !")
# bouton = tk.Button(racine, text="Quitter", fg="red", command=racine.destroy)
# label.pack()
# bouton.pack()
# racine.mainloop()

# from tkinter import *
# from sys import exit
# def popupError(s):
#     popupRoot = Tk()
#     popupRoot.after(2000, exit)
#     popupButton = Button(popupRoot, text = s, font = ("Verdana", 12), bg = "yellow", command = exit)
#     popupButton.pack()
#     popupRoot.geometry('400x50+700+500')
#     popupRoot.pack(side=TOP)
#     popupRoot.mainloop()

# popupError("Erreur hello")

 
# --> 11085
''' PARENT
list_parent_process --> ['9861', '8665', '8633', '8626', '1']
list_child_process --> ['11091']
'''

'''
# M'avertir quand il y a un nouveau processus qui s'execute sur ma machine (mon utilisateur)
'''