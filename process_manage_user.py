import json
import os
import pwd

from env import ALLOW_EXE, DENY_EXE, ALWAYS_ASK_EXE, PROCESS_EXE, PATH_TO_PROCESS_EXE, NOT_EXISTS, KILL_IT, ASK_THEM, ALLOW_IT, FILE_USER_EXE_AUTHORIZATION, FILE_HASH_EXE

from tools import readFromFile, writeInJsonFile, findPathInAuthorization, hashExeSha256

def addUserInJson(user, json_file=FILE_USER_EXE_AUTHORIZATION):
    '''Retourne True si l'ajout d'un utilisateur dans le fichier spécifié dans la variable "FILE_USER_EXE_AUTHORIZATION" sinon None si l'utilisateur est déjà présent.

    @param user Le nom d'un utilisateur.
    @param json_file Chemin du fichier.

    Ajoute dans un fichier une secion avec le nom d'un utilisateur pour pouvoir traiter ces processus.
    '''
    try:
        user_test = pwd.getpwnam(user)
        read_folder = readFromFile(json_file=json_file)
        for rf in read_folder:
            if rf == user:
                return None
        read_folder[user] = {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}
        writeInJsonFile(read_folder, json_file=json_file)
        return True
    except KeyError as k:
        print("[createFolderForSave] Error: {}".format(k))
        return None




def createUserForExeAuthorization():
    '''
    Crée tous les utilisateurs entre le uid 1000 & 60000 pour les stocker dans le fichier qui gère les processus.
    '''
    for user in pwd.getpwall():
        supposed_normal_user = int(user.pw_uid)
        if supposed_normal_user >= 1000 and supposed_normal_user <= 60000:
            print("createUserForExeAuthorization ==> ", user.pw_name)
            addUserInJson(user.pw_name, json_file=FILE_USER_EXE_AUTHORIZATION)


def putFiableExeForUser(path_exe, authorization, type_of_authorization, user="all"):
    '''
    @param path_exe Chemin du fichier.
    @param authorization Le type d'autorisation "ALLOW_EXE", "DENY_EXE".
    @param type_of_authorization Remplace le contenu du fichier par le contenu de la variable "data_json" --> "PROCESS_EXE" ou "PATH_TO_PROCESS_EXE".
    @param user Spécifie l'utilisateur.

    Permet de mettre dans le fichier et/ou dossier une action spécifique pour gérer un processus. L'autorisation sera ecrit dans le fichier 
    permettant de gérer les processus "FILE_USER_EXE_AUTHORIZATION".
    '''
    path_exe = os.path.abspath(path_exe)
    if os.path.exists(path_exe):
        if not os.path.isdir(path_exe):
            reformate_without_filename = hashExeSha256(path_exe)
            all_sha256_exe = readFromFile(json_file=FILE_HASH_EXE)
            all_sha256_exe[path_exe] = reformate_without_filename
            writeInJsonFile(all_sha256_exe, json_file=FILE_HASH_EXE)
        user_exe_authorization = readFromFile(json_file=FILE_USER_EXE_AUTHORIZATION)
        if not (path_exe in user_exe_authorization[user][authorization][type_of_authorization]):
            user_exe_authorization[user][authorization][type_of_authorization].append(path_exe)
            writeInJsonFile(user_exe_authorization)



def authorizationForUser(path_exe, user, type_of_authorization):
    ''' Retourne un tuple comprenant l'action sur un processus (Allow ou deny) et sa signature en SHA256 sinon None.
    @param path_exe Chemin du fichier.
    @param user Utilisateur.
    @param type_of_authorization Remplace le contenu du fichier par le contenu de la variable "data_json" --> "PROCESS_EXE" ou "PATH_TO_PROCESS_EXE".

    Permet de trouver une autorisation faite par un utilisateur spécifique.
    '''
    user_exe_authorization = readFromFile(json_file=FILE_USER_EXE_AUTHORIZATION)
    all_sha256_exe = readFromFile(json_file=FILE_HASH_EXE)
    if type_of_authorization == PROCESS_EXE:
        if path_exe in user_exe_authorization[user][DENY_EXE][type_of_authorization]:
            return DENY_EXE, all_sha256_exe[path_exe]
        if path_exe in user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization]:
            return ALWAYS_ASK_EXE, all_sha256_exe[path_exe]
        if path_exe in user_exe_authorization[user][ALLOW_EXE][type_of_authorization]:
            return ALLOW_EXE, all_sha256_exe[path_exe]
    elif type_of_authorization == PATH_TO_PROCESS_EXE:
        find_path_refuse = findPathInAuthorization(user_exe_authorization[user][DENY_EXE][type_of_authorization], path_exe)
        find_path_always_ask = findPathInAuthorization(user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization], path_exe)
        find_path_accept = findPathInAuthorization(user_exe_authorization[user][ALLOW_EXE][type_of_authorization], path_exe)
        if find_path_refuse != None:
            return DENY_EXE, find_path_refuse
        if find_path_always_ask != None:
            return ALWAYS_ASK_EXE, find_path_always_ask
        if find_path_accept != None:
            return ALLOW_EXE, find_path_accept
    return None


def getAuthorizedShaForUser(path_exe, user, type_of_authorization):
    ''' Retourne les données de "authorizationForUser" sinon None.
    
    @param path_exe Chemin du fichier.
    @param user Utilisateur.
    @param type_of_authorization Remplace le contenu du fichier par le contenu de la variable "data_json" --> "PROCESS_EXE" ou "PATH_TO_PROCESS_EXE".

    Cherche les autorisations de tous les utilisateurs puis d'un utilisateur spécifiques. Sinon rien.
    '''
    all_user = authorizationForUser(path_exe, "all", type_of_authorization)
    if all_user != None:
        return all_user
    specific_user = authorizationForUser(path_exe, user, type_of_authorization)
    if specific_user != None:
        return specific_user
    return None


def manageAuthorizationExecutionForUser(path_exe, user):
    '''Retourne un tuple comprenant l'action sur un processus (Allow ou deny).

    @param path_exe Chemin du fichier.
    @param user Utilisateur.

    Permet de trouver une autorisation faite par un utilisateur spécifique.
    '''
    get_authorization_hash_user_path = getAuthorizedShaForUser(path_exe, user, PATH_TO_PROCESS_EXE)
    if get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == DENY_EXE:
        print("Deny path : {}".format(get_authorization_hash_user_path[1]))
        return KILL_IT, get_authorization_hash_user_path

    get_authorization_hash_user_process = getAuthorizedShaForUser(path_exe, user, PROCESS_EXE)
    hash_exe = hashExeSha256(path_exe)

    if get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == DENY_EXE and get_authorization_hash_user_process[1] == hash_exe:
        print("Deny process : {}".format(get_authorization_hash_user_process[1]))
        return KILL_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == ALLOW_EXE and get_authorization_hash_user_process[1] == hash_exe:
        return ALLOW_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == ALLOW_EXE:
        return ALLOW_IT, get_authorization_hash_user_process
        
    return ASK_THEM, get_authorization_hash_user_process


def manageProcessAuthorizationExe(path_exe, type_of_authorization, user, authorization_exe=""):
    '''Retourne l'autorisation passé en paramètre
    
    @param path_exe Chemin du fichier.
    @param type_of_authorization Remplace le contenu du fichier par le contenu de la variable "data_json" --> "PROCESS_EXE" ou "PATH_TO_PROCESS_EXE".
    @param user Utilisateur.
    @param authorization_exe Action mise en place pour l'autorisation du processus/binaire executé.

    Mets en place une action spécifique pour gérer un processus dans le fichier permettant de gérer les processus.
    '''
    str_authorization = ""
    if type_of_authorization == "PROCESS":
        str_authorization = "Accepter, refuser ou toujours demander l'autorisation d'utiliser le binaire '{}' [acc/den/ask] ? ".format(path_exe)
    else:
        str_authorization = "Accepter, refuser ou toujours demander l'autorisation d'executer un binaire dans le répertoire '{}' [acc/den/ask] ? ".format(path_exe)
    if authorization_exe == "":
        authorization_exe = input(str_authorization)
    if authorization_exe == "acc":
        putFiableExeForUser(path_exe, ALLOW_EXE, type_of_authorization, user=user)
    elif authorization_exe == "den":
        putFiableExeForUser(path_exe, DENY_EXE, type_of_authorization, user=user)
    elif authorization_exe == "ask":
        putFiableExeForUser(path_exe, ALWAYS_ASK_EXE, type_of_authorization, user=user)
    return authorization_exe


def mainProcessAuthorizationExe(path_exe, user, authorization_exe_decision=""):
    '''
    MAIN PROCESSUS

    @param path_exe Chemin du fichier.
    @param user Utilisateur.
    @param authorization_exe_decision Action mise en place pour l'autorisation du processus/binaire executé.

    Permet de mettre en place sur un fichier/dossier une action passé en paramètre.
    '''
    path_exe = os.path.abspath(path_exe)
    type_of_authorization = ""
    if os.path.isfile(path_exe):
        type_of_authorization = PROCESS_EXE
    elif os.path.isdir(path_exe):
        type_of_authorization = PATH_TO_PROCESS_EXE
    else:
        return NOT_EXISTS
    manage_process = manageAuthorizationExecutionForUser(path_exe, user)
    if manage_process[0] == ASK_THEM:
        authorization_exe = ""
        while(authorization_exe != "acc" and authorization_exe != "den" and authorization_exe != "ask"):
            authorization_exe = manageProcessAuthorizationExe(path_exe, type_of_authorization, user, authorization_exe=authorization_exe_decision)
            manage_process = manageAuthorizationExecutionForUser(path_exe, user)
    return manage_process