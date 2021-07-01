from manage_authorization_process import initializeAllConfiguration, mainProcessAuthorizationExe

# Permet d'accepter, refuser ou demander le droit d'executer des binaires dans un répertoire
# main_process_authorization =  mainProcessAuthorizationExe("/home/gespenst/", "gespenst", PATH_TO_PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))

# Permet d'accepter, refuser ou demander le droit d'executer un binaire spécifiquement
# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst", PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))


def handleProcess():
    all_process = psutil.pids()
    new_process = findNewProcess(all_process_allow, all_process)
    print("new_process --> {}".format(new_process))
    kernel_process = getKernelProcess()

    # Faire le trie des process avec le fichier qu'on a mis en place (execution des process dans un chemin, certains process etc)
    # peut-être en faisant du parallélisme.

    # ASK_AGAIN && Non trouvé dans les fichiers
    for np in new_process:
        if not (np in kernel_process):
            ret_resp = call(["kill", "-STOP", str(np)])
            print("[>] Processus {} stoppé.".format(np))
            manageProcessForUser(np)


def main():
    initializeAllConfiguration()
