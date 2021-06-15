import psutil
from subprocess import call, Popen, PIPE, check_output
import time
import os

''' KERNEL PROCESS : 
https://unix.stackexchange.com/questions/411159/linux-is-it-possible-to-see-only-kernel-space-threads-process
ps --ppid 2 -p 2 -o uname,pid,ppid,cmd,cls
'''

pids = psutil.pids()
print("pids ==> {} and last pid {}".format(pids, pids[-2]))

# sudo apt install psmisc --> fuser

# p = psutil.Process(pids[-1])

# p = psutil.Process(9149)
p = psutil.Process(11085)
# p = psutil.Process(2)
print("Specific process --> {}".format(p))

# https://www.linuxquestions.org/questions/linux-kernel-70/which-pids-are-reserved-for-the-kernel-4175417220/
'''
$ cat /proc/9945/task/9945/children
9951
$ readlink -f /proc/9951/exe
/home/gespenst/fraise

# Get parent ID
$ ps -o ppid= -p 9951
9945
'''

# 752 - 747 - 729 - 667 - 661 - 656 - 654 - 645 - 627

# pid (à voir ou dans un autre fichier-bdd), exe, hash
BDD_MAP_SAVE = {"allow": {}, "deny": {}, "waiting": {}}

def getKernelProcess():
    # ps --ppid 2 -p 2 -o pid --no-header
    kernel_process = check_output(["ps", "--ppid", "2", "-p", "2", "-o", "pid", "--no-header"]).decode("latin").strip(' \t\n\r').split("\n")
    for i in range(len(kernel_process)):
        kernel_process[i] = int(kernel_process[i])
    print("kernel_process --> {}".format(kernel_process))
    return kernel_process

def getFileNotFoundInExe(pid):
    # ps eo command -p 12107 --no-header
    # file_not_found_in_exe = check_output(["ps", "eo", "command", "-p", str(pid), "--no-header"]).decode("latin").strip(' \t\n\r').split("\n")
    # print("file_not_found_in_exe --> {}".format(file_not_found_in_exe))

    # ret_pwdx = call(["pwdx", str(pid)])
    # print("ret_pwdx ==> {}".format(ret_pwdx))

    # ret_get_file = os.readlink("/proc/{}/cwd".format(str(pid))) # call(["ls", "-la", "/proc/{}/cwd/".format(str(pid))])
    # print("ret_get_file ==> {}".format(ret_get_file))
    path_executable = []

    file_not_found_in_exe = psutil.Process(pid).as_dict()
    path_exe = file_not_found_in_exe["environ"]["PWD"]
    # print("t --> {} {} {}".format(file_not_found_in_exe["exe"], path_exe, file_not_found_in_exe["cmdline"]))
    for cmd in file_not_found_in_exe["cmdline"]:
        is_path_file_exists = os.path.isfile(path_exe+"/"+cmd) 
        if not is_path_file_exists:
            ret_get_path = check_output("find {} -name {} 2> /dev/null".format(path_exe, cmd), shell=True).decode("latin").strip()
            if(len(ret_get_path) > 0):
                # print("ret_get_path ==> {}".format(ret_get_path))
                path_executable.append(ret_get_path)
        else:
            path_executable.append(os.path.abspath(path_exe+"/"+cmd))
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

# test_pid = 11960
test_pid = 11085
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

exit(1)

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


process_dict = p.as_dict()
findFiles(process_dict)

# Tout les pid qui ont pour parent 
# permettre à python3 d'être executé
# regarder les options pour voir si c'est des options ou fichiers
# utiliser la commande ps (plus facile et moins compliqué pour trouver les processus)

print("status : {}\nUsername : {}\nCreateTime : {}\nOpen file : {}\nConnection : {}\nDict : {}".format(
    p.status(),
    p.username(),
    p.create_time(),
    p.open_files(),
    p.connections(kind='tcp'),
    p.as_dict()
))
exit(1)

# pwdx 7844

print("\nPid : {}\nPath : {}\nCommand Line : {}\nUsername : {}\nSSH CONNECTION ---\nLOGNAME : {}\nSsh : {}\n".format(
    process_dict["pid"],
    process_dict["cwd"],
    process_dict["cmdline"],
    process_dict["environ"]["USER"] if "USER" in process_dict["environ"] else None,
    process_dict["environ"]["LOGNAME"] if "LOGNAME" in process_dict["environ"] else None,
    process_dict["environ"]["SSH_CONNECTION"] if "SSH_CONNECTION" in process_dict["environ"] else None,
))

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

def getFileFromProcess(process):
    print("[>] getFileFromProcess")
    process_dict = process.as_dict()
    pid = process_dict["pid"]
    ret_resp = call(["pwdx", str(pid)])
    print("ret_resp ==> {}".format(ret_resp))
    # findFiles



all_process_allow = psutil.pids()
all_process_refuse = []

def findNewProcess(all_process_allow, all_process):
    new_process = []
    for ap in all_process:
        if not (ap in all_process_allow):
            new_process.append(ap)
    return new_process

def handleProcess():
    all_process = psutil.pids()
    new_process = findNewProcess(all_process_allow, all_process)
    print("new_process --> {}".format(new_process))
    for np in new_process:
        ret_resp = call(["kill", "-STOP", str(np)])
        print("[>] Processus {} stoppé.".format(np))
        manageProcessForUser(np)

def manageProcessForUser(pid):
    print("p.name : {}".format(p.as_dict()["name"]))
    if p.as_dict()["name"] == 'python3':
        response_kill = ""
        while(response_kill != "y" and response_kill != "n"):
            response_kill = input("Voulez-vous tuer le process ou pas [y/n] ? ")
            print("response_kill => {}".format(response_kill))
            if(response_kill == 'y'):
                print("Kill du processus {} en cours...".format(pid))
                ret_resp = call(["kill", str(pid)])
                print("kill ==> {}".format(ret_resp))
            elif response_kill == "n":
                ret_resp = call(["kill", "-CONT", str(pid)])
                all_process_allow.append(pid)


# getFileFromProcess(p)

while(1):
    print("handle_process")
    handleProcess()
    time.sleep(5)




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