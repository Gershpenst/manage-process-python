import psutil
import time

from manage_authorization_process import readFromFile, writeInJsonFile, initializeAllConfiguration, mainProcessAuthorizationExe, manageAuthorizationExecutionForUser, FILE_ALL_PROCESS_PID_WAITING, PROCESS_EXE, KILL_IT, ASK_THEM, ALLOW_IT
from manage_process import getKernelProcess, getFileNotFoundInExe, waitingForAction

# Permet d'accepter, refuser ou demander le droit d'executer des binaires dans un répertoire
# main_process_authorization =  mainProcessAuthorizationExe("/home/gespenst/", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))

# Permet d'accepter, refuser ou demander le droit d'executer un binaire spécifiquement
# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))


NBR_WAIT_FOR_ACTION = 24

def initializeAllPresentProcess():
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


# initializeAllPresentProcess()

def handleProcess():
    all_process = psutil.pids()
    kernel_process = getKernelProcess()
    new_process = [ap for ap in all_process if ap not in kernel_process]

    #####
    # Trouver la personne qui execute ce fichier
    #####

    for np in new_process:
        try:
            ps_process = psutil.Process(np)
            cmdline = ps_process.cmdline()
            path_not_found = getFileNotFoundInExe(np)
            if len(path_not_found) > 0:
                for pnf in path_not_found:
                    manage_process = manageAuthorizationExecutionForUser(pnf, "gespenst")
                    if manage_process[0] == KILL_IT:
                        print("Kill du processus --> {}".format(np))
                        ps_process.kill()
                    elif manage_process[0] != ALLOW_IT:
                        print("Stop du processus --> {}".format(np))
                        # print("\n\ncmdline --> {}".format(cmdline))
                        # print("Process_manage --> {} -- {}".format(pnf, manage_process))
                        waiting_processes = readFromFile(json_file=FILE_ALL_PROCESS_PID_WAITING)
                        print("waiting_processes --> {}".format(waiting_processes))
                        if not (str(np) in waiting_processes):
                            waiting_processes[str(np)] = [NBR_WAIT_FOR_ACTION, pnf]
                        waiting_processes = waitingForAction(str(np), "gespenst", waiting_processes)
                        print("waiting_processes ---> {}".format(waiting_processes))
                        writeInJsonFile(waiting_processes, json_file=FILE_ALL_PROCESS_PID_WAITING)
                        # print("Suspend process --> ")
                        # ps_process.suspend() # stop process
                        # time.sleep(10)

                        # main_process_authorization =  mainProcessAuthorizationExe(pnf, "gespenst", authorization_exe_decision="den")
                        # print("Process_manage --> {} -- {}".format(pnf, main_process_authorization))
        except psutil.AccessDenied:
            continue
        except psutil.NoSuchProcess:
            continue

    return new_process

# Process_manage --> /home/gespenst/manage-process-python/main.py -- (0, ('allow', '9094936f464be4a2463f3843cae449c8d33a6d2a9e0e2625f47c14e4ee5219ec'))

# initializeAllPresentProcess()

# def handleProcess():
#     all_process = psutil.pids()
#     new_process = findNewProcess(all_process_allow, all_process)
#     print("new_process --> {}".format(new_process))
#     kernel_process = getKernelProcess()

#     # Faire le trie des process avec le fichier qu'on a mis en place (execution des process dans un chemin, certains process etc)
#     # peut-être en faisant du parallélisme.

#     # ASK_AGAIN && Non trouvé dans les fichiers
#     for np in new_process:
#         if not (np in kernel_process):
#             ret_resp = call(["kill", "-STOP", str(np)])
#             print("[>] Processus {} stoppé.".format(np))
#             manageProcessForUser(np)


def main():
    initializeAllPresentProcess()
    while(1):
        print("handle_process")
        handleProcess()
        time.sleep(5)

main()