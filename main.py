import psutil
import os
import time

from env import ALLOW_IT, FILE_ALL_PROCESS_PID_WAITING, KILL_IT, NBR_WAIT_FOR_ACTION
from manage_process import getKernelProcess, getFileNotFoundInExe, waitingForAction, verifyProcessExists
from process_manage_user import mainProcessAuthorizationExe, manageAuthorizationExecutionForUser
from tools import readFromFile, writeInJsonFile, initializeAllConfiguration

def initializeAllPresentProcess():
    '''
    /!\ Cette fonction est executé une seule fois.
    Initialise tous les processus dans les fichiers créés  à partir de la fonction "initializeAllConfiguration".
    Ces processus sont tous acceptés d'office afin de générer un fichier regroupant déjà des processus autorisés.
    C'est pour cela qu'il est recommandé d'executé ce script sur un environnement sain.
    '''
    initialize_configuration = initializeAllConfiguration()
    all_process = psutil.pids()
    kernel_process = getKernelProcess()
    new_process = [ap for ap in all_process if ap not in kernel_process]

    if initialize_configuration:
        for np in new_process:
            try:
                ps_process = psutil.Process(np)
                cmdline = ps_process.cmdline()
                path_not_found = getFileNotFoundInExe(np)
                if len(path_not_found) > 0:
                    for pnf in path_not_found:
                        main_process_authorization =  mainProcessAuthorizationExe(pnf, "all", authorization_exe_decision="acc")
                        # print("Process_manage --> {} -- {}".format(pnf, main_process_authorization))
                # sss = input("PASS : ")
            except psutil.AccessDenied:
                continue
            except psutil.NoSuchProcess:
                continue
    return new_process


def handleProcess():
    '''
    Permet de gérer les processus des utilisateurs. Lorsqu'un processus inconnus est trouvé à partir du fichier regroupant les processus initialisés,
    celui-ci est arrêté et est soumis à une analyse manuelle de l'utilisateur. Si l'utilisateur trouve que le fichier est inofensif, l'utilisateur pourra
    lever l'exception à partir des fonctions CLI développées. Sinon le processus sera "deny" et kill.
    '''
    all_process = psutil.pids()
    kernel_process = getKernelProcess()
    new_process = [ap for ap in all_process if ap not in kernel_process]

    #####
    # Trouver la personne qui execute ce fichier
    #####

    waiting_processes = readFromFile(json_file=FILE_ALL_PROCESS_PID_WAITING)
    waiting_processes = verifyProcessExists(waiting_processes)
    print("verify_process_exists --> {}".format(waiting_processes)) 

    for np in new_process:
        try:
            ps_process = psutil.Process(np)
            cmdline = ps_process.cmdline()
            path_not_found = getFileNotFoundInExe(np)
            if len(path_not_found) > 0:
                for pnf in path_not_found:
                    manage_process = manageAuthorizationExecutionForUser(pnf, os.getlogin())
                    if manage_process[0] == KILL_IT:
                        print("Kill du processus --> {}".format(np))
                        ps_process.kill()
                    elif manage_process[0] != ALLOW_IT:
                        print("Stop du processus --> {}".format(np))
                        if not (str(np) in waiting_processes):
                            waiting_processes[str(np)] = [NBR_WAIT_FOR_ACTION, pnf]
                        waiting_processes = waitingForAction(str(np), os.getlogin(), waiting_processes)
                        print("waiting_processes ---> {}".format(waiting_processes))
                        writeInJsonFile(waiting_processes, json_file=FILE_ALL_PROCESS_PID_WAITING)
        except psutil.AccessDenied:
            continue
        except psutil.NoSuchProcess:
            continue

    return new_process


if __name__ == "__main__":
    initializeAllPresentProcess()
    while(1):
        handleProcess()
        time.sleep(5)


'''
Virus total (pour vérifier les hash des fichiers)
'''