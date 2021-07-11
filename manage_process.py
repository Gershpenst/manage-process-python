import psutil
from subprocess import Popen, PIPE, check_output, DEVNULL
import time
import os
from glob import glob

from process_manage_user import mainProcessAuthorizationExe
from tools import readFromFile, writeInJsonFile
from env import FILE_ALL_PROCESS_PID_WAITING


def getKernelProcess():
    '''Retourne tous les processus du Kernel.
    '''
    kernel_process = check_output(["ps", "--ppid", "2", "-p", "2", "-o", "pid", "--no-header"]).decode("latin").strip(' \t\n\r').split("\n")
    kernel_process.append(1)
    for i in range(len(kernel_process)):
        kernel_process[i] = int(kernel_process[i])
    return kernel_process

def removeItemInList(lst, item):
    '''Retourne la liste "lst"

    @param lst la liste où enlever un item
    @param item item a enlevé de la liste
    
    Supprime un item d'une liste
    '''
    try:
        return lst.remove(item)
    except Exception:
        return lst


def whereisPathForCommand(cmd):
    '''Retourne le chemin où se trouve le binaire sinon None.

    @param cmd Une commande a cherché (ex : bash, ssh, etc)
    Trouve le chemin d'un binaire.
    '''
    whereis_cmd = Popen(('whereis', "-b", cmd), stdout=PIPE, stderr=DEVNULL)
    reformate_whereis_cmd = check_output(('cut', '-d', ' ', '-f', '2'), stdin=whereis_cmd.stdout).decode("latin").strip()
    whereis_cmd.wait()
    if reformate_whereis_cmd == "" or reformate_whereis_cmd[-1] == ":":
        return None
    return reformate_whereis_cmd

def getFileNotFoundInExe(pid):
    '''Retoune les chemins des fichiers trouvées dans la section /proc/<pid>/cwd

    @param pid L'id d'un processus

    Permet de recupérer tous les chemins où sont executé des fichiers dans un processus
    '''
    path_executable = []
    file_not_found_in_exe = psutil.Process(pid).as_dict()
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
    
        try_list_path = [cmd, path_exe+"/"+cmd]
        for path_file in try_list_path:
            is_path_file_exists = os.path.isfile(path_file)
            

            path_folder_file = glob(path_file)
            if len(path_folder_file) > 0 and not os.path.isdir(path_file):
                for pff in path_folder_file:
                    path_executable.append(os.path.abspath(pff))
                break
    
    path_executable = removeItemInList(path_executable, ".")
    path_executable = removeItemInList(path_executable, "..")
    return path_executable



def waitingForAction(pid, user, waiting_processes, DENY_AFTER_TIME_PASS=True):
    '''Retourne un dcitionnaire contenant tous les processus en attente d'action par un utilisateur.

    @param pid L'id d'un processus.
    @param user Un utilisateur.
    @param waiting_processes Un dictionnaire contenant tous les processus en attente
    @param DENY_AFTER_TIME_PASS Refuse un processus lorsque le compteur est égale à 0.

    Permet de stopper un processus, de décrémenter le compteur pour chaque processus en attente et de le kill si celui-ci atteint 0.
    '''
    psutil_pid = psutil.Process(int(pid))
    print("psutil_pid --> {}".format(psutil_pid))
    waiting_processes[pid][0] -= 1
    psutil_pid.suspend()

    if waiting_processes[pid][0] < 0:
        if DENY_AFTER_TIME_PASS:
            main_process_authorization =  mainProcessAuthorizationExe(waiting_processes[pid][1], user, authorization_exe_decision="den")
            print("main_process_authorization ---> {}".format(main_process_authorization))
        waiting_processes.pop(pid)
        psutil_pid.kill()
    return waiting_processes


def verifyProcessExists(waiting_processes):
    '''Retourne les processus en attente.

    @param waiting_processes Les processus en attente

    Enlève un processus dans le dictionnaire des processus en attente lorsque celui-ci n'existe plus.
    '''
    waiting_processes_copy = waiting_processes.copy()
    for wp in waiting_processes:
        try:
            psutil_pid = psutil.Process(int(wp))
        except psutil.NoSuchProcess as nsp:
            waiting_processes_copy.pop(wp)
    writeInJsonFile(waiting_processes_copy, json_file=FILE_ALL_PROCESS_PID_WAITING, replace_all_content_file=True)
    return waiting_processes


def responseForAction(pid, user, action):
    '''Retourne les processus en attente.

    @param pid L'id d'un processus.
    @param user Un utilisateur.
    @param action Action pour "accepter", "refuser".

    Permet de mettre en place sur un fichier/dossier une action passé en paramètre. Applique une action
    lorsque celui-ci a été défini dans le fichier de processus.
    '''
    try:
        psutil_pid = psutil.Process(pid)
        waiting_processes = readFromFile(json_file=FILE_ALL_PROCESS_PID_WAITING)
        main_process_authorization =  mainProcessAuthorizationExe(waiting_processes[str(pid)][1], user, authorization_exe_decision=action)
        if action == "den":
            psutil_pid.kill()
        elif action == "acc" or action == "ask":
            psutil_pid.resume()
        waiting_processes.pop(str(pid))
        writeInJsonFile(waiting_processes, json_file=FILE_ALL_PROCESS_PID_WAITING, replace_all_content_file=True)
        return waiting_processes
    except KeyError as ke:
        print("Aucun processus {} en attente d'action.".format(pid))
    except psutil.NoSuchProcess as nsp:
        print(nsp)
    except Exception as e:
        print("Une erreur est survenue.")
        print(e)
    return None