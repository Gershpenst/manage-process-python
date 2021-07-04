import argparse
import json
import os
import psutil
import pwd
from manage_authorization_process import readFromFile, mainProcessAuthorizationExe, manageAuthorizationExecutionForUser, addUserInJson, PROCESS_EXE, KILL_IT, ASK_THEM, ALLOW_IT, ALLOW_EXE, DENY_EXE, ALWAYS_ASK_EXE, FILE_ALL_PROCESS_PID_WAITING, PATH_TO_PROCESS_EXE, writeInJsonFile
from manage_process import getFileNotFoundInExe, responseForAction

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--action", type=str, help="Action pour gérer un processus.", required=True)
parser.add_argument("-d", "--path_folder", type=str, help="Chemin du dossier pour appliquer une action.")
parser.add_argument("-f", "--path_file", type=str, help="Chemin du fichier pour appliquer une action.")
parser.add_argument("-p", "--pid", type=int, help="Pid du processus pour appliquer une action.")

parser.add_argument("-u", "--user", type=str, help="Action pour un utilisateur spécifiques. Si l'utilisateur n'existe pas dans le fichier JSON, celui-ci se créera.")
parser.add_argument("-s", "--suppress", type=str, help="Supprime une action dans la liste des actions.")
parser.add_argument("-l", "--list_action", help="Liste les actions fait sur certains processus au format json.", action='store_true')
parser.add_argument("-w", "--waiting_process", help="Liste les processus en attente d'actions.", action='store_true')


# parser.add_argument("-rm", "--remove_", type=str, help="Enlève un attribut dans le json")

args = parser.parse_args()

USER = "all"

def getAction(action):
    # ALLOW_EXE, DENY_EXE, ALWAYS_ASK_EXE
    if action == "acc":
        return ALLOW_EXE
    elif action == "den":
        return DENY_EXE
    elif action == "ask":
        return ALWAYS_ASK_EXE
    else:
        return None

if args.action == None:
    # parser.error("--prox requires --lport and --rport.")
    parser.print_help()
    exit(-1)
elif args.action != "acc" and args.action != "den":# and args.action != "ask":
    print("Les actions pour gérer les processus :\n\t- {}\n\t- {}\n".format("acc", "den")) #, "ask"))
    parser.print_help()
    exit(-1)

if args.user != None and args.user != "all":
    try:
        pwd.getpwnam(args.user)
        addUserInJson(args.user)
        USER = args.user
    except KeyError:
        print("L'utilisateur {} n'existe pas.".format(args.user))

if args.path_folder != None:
    if os.path.isdir(args.path_folder):
        main_process_authorization =  mainProcessAuthorizationExe(args.path_folder, USER, authorization_exe_decision=args.action)
        print("main_process_authorization --> {}".format(main_process_authorization))
    else:
        print("[Erreur] Le dossier {} n'existe pas.".format(args.path_folder))
elif args.path_file != None:
    if os.path.isfile(args.path_file):
        main_process_authorization =  mainProcessAuthorizationExe(args.path_file, USER, authorization_exe_decision=args.action)
        print("main_process_authorization --> {}".format(main_process_authorization))
    else:
        print("[Erreur] Le fichier {} n'existe pas.".format(args.path_file))
elif args.pid != None:
    pid = args.pid
    # print("pid ---> {}".format(pid))
    # Pourquoi pas utiliser cette fonction : "responseForAction" au lieu du code d'en bas
    responseForAction(args.pid, USER, args.action)

    # if psutil.pid_exists(pid):
    #     ps_process = psutil.Process(pid)
    #     cmdline = ps_process.cmdline()
    #     path_not_found = getFileNotFoundInExe(pid)
    #     if len(path_not_found) > 0:
    #         for pnf in path_not_found:
    #             main_process_authorization =  mainProcessAuthorizationExe(pnf, USER, authorization_exe_decision=args.action)
    # else:
    #     print("[Erreur] Le pid {} n'existe pas.".format(args.pid))
elif args.list_action != None and args.list_action:
    print("args.list_action --> {}".format(args.list_action))
    read_authorization_exe = readFromFile()
    action = getAction(args.action)
    if action != None:
        print(json.dumps(read_authorization_exe[USER][action], sort_keys=True, indent=4))
    else:
        print("Aucune action {} n'a été mise en place.".format(action))
elif args.waiting_process != None and args.waiting_process:
    read_wainting_process = readFromFile(json_file=FILE_ALL_PROCESS_PID_WAITING)
    print(json.dumps(read_wainting_process, sort_keys=True, indent=4))
elif args.suppress != None:
    print("args.list_action --> {}".format(args.list_action))
    read_authorization_exe = readFromFile()
    action = getAction(args.action)
    if action != None:
        try:
            action_path = None
            if os.path.isdir(args.suppress):
                action_path = PATH_TO_PROCESS_EXE
            elif os.path.isfile(args.suppress):
                action_path = PROCESS_EXE
            else:
                print("Le chemin ou dossier n'existe pas.")
                exit(1)
            
            read_authorization_exe[USER][action][action_path].remove(args.suppress)
            writeInJsonFile(read_authorization_exe)
            print("test ----> {}\n".format(read_authorization_exe))

        except KeyError as ke:
            print("[KeyError] {}".format(ke))
        except ValueError:
            print("Le chemin {} n'existe pas dans l'action {} chez l'utilisateur {}.".format(args.suppress, args.action, USER))
    else:
        print("Aucune action {} n'a été mise en place.".format(action))
else:
    parser.print_help()
    exit(-1)

# if args.iface == None:
#     print("Veuillez sépcifier votre interface.\n")
#     parser.print_help()
#     exit(-1)
# else:
#     NETWORK_INTERFACE = args.iface

# if args.count != None and args.count > 0:
#     COUNT_SNIFF = args.count

# if args.file != None and args.file[-5:] == ".pcap":
#     FILE_SAVE_PCAP = args.file



# Permet d'accepter, refuser ou demander le droit d'executer des binaires dans un répertoire
# main_process_authorization =  mainProcessAuthorizationExe("/home/gespenst/", "gespenst", PATH_TO_PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))

# Permet d'accepter, refuser ou demander le droit d'executer un binaire spécifiquement
# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst", PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))

# main_process_authorization =  mainProcessAuthorizationExe(pnf, "all", PROCESS_EXE, authorization_exe_decision="acc")

                        
# print("Suspend process --> ")
# ps_process.suspend() # stop process
# time.sleep(10)

# # print("Resume process --> ")
# # ps_process.resume()
# # time.sleep(10)

# print("Kill process --> ")
# ps_process.kill()
# time.sleep(10)
# sss = input("PASS : ")