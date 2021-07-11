import argparse
import json
import os
import pwd

from tools import readFromFile, writeInJsonFile
from process_manage_user import mainProcessAuthorizationExe, addUserInJson
from manage_process import responseForAction

from env import ALLOW_EXE, DENY_EXE, ALWAYS_ASK_EXE, PROCESS_EXE, PATH_TO_PROCESS_EXE, FILE_ALL_PROCESS_PID_WAITING

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--action", type=str, help="Action pour gérer un processus.", required=True)
parser.add_argument("-d", "--path_folder", type=str, help="Chemin du dossier pour appliquer une action.")
parser.add_argument("-f", "--path_file", type=str, help="Chemin du fichier pour appliquer une action.")
parser.add_argument("-p", "--pid", type=int, help="Pid du processus pour appliquer une action.")

parser.add_argument("-u", "--user", type=str, help="Action pour un utilisateur spécifiques. Si l'utilisateur n'existe pas dans le fichier JSON, celui-ci se créera.")
parser.add_argument("-s", "--suppress", type=str, help="Supprime une action dans la liste des actions.")
parser.add_argument("-l", "--list_action", help="Liste les actions fait sur certains processus au format json.", action='store_true')
parser.add_argument("-w", "--waiting_process", help="Liste les processus en attente d'actions.", action='store_true')

args = parser.parse_args()

USER = "all"

def getAction(action):
    '''
    Permet de trouver les bonnes énumérations afin d'appliquer une action sur un processus 
    '''
    if action == "acc":
        return ALLOW_EXE
    elif action == "den":
        return DENY_EXE
    elif action == "ask":
        return ALWAYS_ASK_EXE
    else:
        return None

if __name__ == "__main__":
    '''
    MAIN CLI
    '''
    if args.action == None:
        parser.print_help()
        exit(-1)
    elif args.action != "acc" and args.action != "den":
        print("Les actions pour gérer les processus :\n\t- {}\n\t- {}\n".format("acc", "den"))
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
        responseForAction(args.pid, USER, args.action)
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