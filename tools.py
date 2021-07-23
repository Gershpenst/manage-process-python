import json
import os
import pwd
import shutil
from subprocess import call, Popen, PIPE, check_output

from env import ALLOW_EXE, DENY_EXE, ALWAYS_ASK_EXE, PROCESS_EXE, PATH_TO_PROCESS_EXE, NAME_OF_SCRIPT, COPY_FILE_TO, FOLDER_SAVING_EVENT, FILE_USER_EXE_AUTHORIZATION, FILE_HASH_EXE, FILE_ALL_PROCESS_PID_WAITING


def hashExeSha256(path_exe):
    '''Retourne un hash en sha-256 d'un fichier sinon une chaîne de caractèe vide.
    
    @param path_exe Chemin du fichier

    Retourne le SHA d'un fichier en particulier.
    '''
    if os.path.isfile(path_exe):
        path_exe = os.path.abspath(path_exe)
        sha256sum = Popen(('sha256sum', path_exe), stdout=PIPE)
        reformate_without_filename = check_output(('cut', '-d', ' ', '-f', '1'), stdin=sha256sum.stdout).decode("latin").strip()
        sha256sum.wait()
        return reformate_without_filename
    return ""

def createFolderForSave():
    '''Retourne "True" si le dossier est créé sinon None ou False.
    Permet de créer le dossier spécifié dans la variable "FOLDER_SAVING_EVENT".
    '''
    try:
        os.mkdir(FOLDER_SAVING_EVENT)
        return True
    except KeyError as k:
        print("[createFolderForSave] Error: {}".format(k))
        return None
    except FileExistsError as fee:
        print("Le fichier existe.")
        return False

def readFromFile(json_file=FILE_USER_EXE_AUTHORIZATION):
    '''Retourne les données écrit dans le fichier. Sinon un dictionnaire vide.

    @param json_file Chemin du fichier.

    Lit un fichier et retourne son contenu.
    '''
    if os.path.isfile(json_file):
        json_file_read = open(json_file, "r")
        data_from_file = json.load(json_file_read)
        json_file_read.close()
        return data_from_file
    return {}


def writeInJsonFile(data_json, json_file=FILE_USER_EXE_AUTHORIZATION, replace_all_content_file=False):
    '''Retourne True si tout s'est bien passé.

    @param data_json Les données à écrire.
    @param json_file Chemin du fichier.
    @param replace_all_content_file Remplace le contenu du fichier par le contenu de la variable "data_json".

    Ecrit dans le fichier spécifié en paramètre.
    '''
    read_data_json = readFromFile(json_file=json_file)
    json_file_write = open(json_file, "w")
    
    if replace_all_content_file:
        json_file_write.write(json.dumps(data_json))
    else:
        read_data_json.update(data_json)
        json_file_write.write(json.dumps(read_data_json))
    json_file_write.close()
    return True


def initializeAllConfiguration():
    '''Retourne True si une configuration a été mise en place sinon False.

    Permet d'initialiser les dossiers et fichiers pour le bon fonctionnement du programme.
    '''
    from process_manage_user import addUserInJson
    initialize_configuration = False
    if not os.path.isdir(FOLDER_SAVING_EVENT):
        createFolderForSave()
        initialize_configuration = True

    try:
        shutil.copy2(NAME_OF_SCRIPT, COPY_FILE_TO)
    except shutil.SameFileError as sfe:
        pass

    if not os.path.isfile(FILE_USER_EXE_AUTHORIZATION):
        user_exe_authorization = {"all": {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}}
        writeInJsonFile(user_exe_authorization)
        initialize_configuration = True

    if not os.path.isfile(FILE_HASH_EXE):
        destination_file = os.path.abspath(COPY_FILE_TO + "/" + NAME_OF_SCRIPT)
        hash_exe = hashExeSha256(destination_file)
        all_sha256_exe = {destination_file : hash_exe}
        writeInJsonFile(all_sha256_exe, json_file=FILE_HASH_EXE)
        initialize_configuration = True

    writeInJsonFile({}, json_file=FILE_ALL_PROCESS_PID_WAITING, replace_all_content_file=True)

    user_uid = os.geteuid()
    if user_uid == 0:
        from process_manage_user import createUserForExeAuthorization
        createUserForExeAuthorization()
    else:
        user_name = pwd.getpwuid(user_uid).pw_name
        print("user_name ==> {}".format(user_name))
        addUserInJson(user_name)

    return initialize_configuration


def findPathInAuthorization(list_of_paths, path_to_find):
    '''Retourne le chemin trouvé sinon None.

    @param path_to_find Chemin qui doit être trouvé.
    @param list_of_paths Liste de chemin.

    Permet de chercher un chemin "path_to_find" dans le dictionnaire regroupant les chemins connus "list_of_paths".
    '''
    for lop in list_of_paths:
        if lop in path_to_find:
            return lop
    return None


