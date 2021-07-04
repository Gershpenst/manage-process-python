import json
import os
import pwd
import shutil
from subprocess import call, Popen, PIPE, check_output

ALLOW_EXE = "allow"
DENY_EXE = "deny"
ALWAYS_ASK_EXE = "always_ask"

PROCESS_EXE = "PROCESS"
PATH_TO_PROCESS_EXE = "PATH_EXE_PROCESS"


NOT_EXISTS = -2
KILL_IT = -1
ASK_THEM = 0
ALLOW_IT = 1

NAME_OF_SCRIPT = os.path.basename(__file__)
COPY_FILE_TO = "."
FOLDER_SAVING_EVENT = os.environ["HOME"]+"/PROJECT_PYTHON_WITH_NO_NAME"
FILE_USER_EXE_AUTHORIZATION = FOLDER_SAVING_EVENT+"/AUTHORIZATION_EXE.json"
FILE_HASH_EXE = FOLDER_SAVING_EVENT+"/FILE_HASH_EXE.json"
FILE_ALL_PROCESS_PID_WAITING = FOLDER_SAVING_EVENT+"/all_process_tmp.json"

# print("pwd.getpwall() --> {}".format(pwd.getpwnam("gespenst").pw_dir))
# print(os) # getpid(), getppid()
# print("geteuid --> ", os.geteuid())
# print("geteuid --> ", os.environ["HOME"])

def hashExeSha256(path_exe):
    if os.path.isfile(path_exe):
        path_exe = os.path.abspath(path_exe)
        sha256sum = Popen(('sha256sum', path_exe), stdout=PIPE)
        reformate_without_filename = check_output(('cut', '-d', ' ', '-f', '1'), stdin=sha256sum.stdout).decode("latin").strip()
        sha256sum.wait()
        return reformate_without_filename
    return ""

def createFolderForSave():
    try:
        os.mkdir(FOLDER_SAVING_EVENT)
    except KeyError as k:
        print("[createFolderForSave] Error: {}".format(k))
        return None
    except FileExistsError as fee:
        print("Le fichier existe.")
        return False

def readFromFile(json_file=FILE_USER_EXE_AUTHORIZATION):
    if os.path.isfile(json_file):
        json_file_read = open(json_file, "r")
        data_from_file = json.load(json_file_read)
        json_file_read.close()
        return data_from_file
    return {}

# def writeInJsonFile(data_json, json_file=FILE_USER_EXE_AUTHORIZATION, replace_all_content_file=False):
#     json_file_write = open(json_file, "w")
#     if replace_all_content_file:
#         json_file_write.write(json.dumps(data_json))
#     else:
#         read_data_json = readFromFile(json_file=json_file)
#         read_data_json.update(data_json)
#         json_file_write.write(json.dumps(read_data_json))
#         read_data_json.close()
#     json_file_write.close()
#     return True
def writeInJsonFile(data_json, json_file=FILE_USER_EXE_AUTHORIZATION, replace_all_content_file=False):
    # print("replace_all_content_file -----------------------------> {}".format(replace_all_content_file))
    # read_data_json = readFromFile(json_file=json_file)
    # json_file_write = open(json_file, "w")
    # read_data_json.update(data_json)
    # json_file_write.write(json.dumps(read_data_json))
    # json_file_write.close()
    

    read_data_json = readFromFile(json_file=json_file)

    print("\n\ndata_json --> {}".format(data_json))
    print("read_data_json --> {}".format(read_data_json))

    json_file_write = open(json_file, "w")
    print("data_json ---> {}".format(data_json))
    if replace_all_content_file:
        json_file_write.write(json.dumps(data_json))
    else:
        read_data_json.update(data_json)
        json_file_write.write(json.dumps(read_data_json))
    json_file_write.close()
    return True

def addUserInJson(user, json_file=FILE_USER_EXE_AUTHORIZATION):
    try:
        user_test = pwd.getpwnam(user)
        read_folder = readFromFile(json_file=json_file)
        for rf in read_folder:
            if rf == user:
                return None
        read_folder[user] = {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}
        writeInJsonFile(read_folder, json_file=json_file)
    except KeyError as k:
        print("[createFolderForSave] Error: {}".format(k))
        return None

def initializeAllConfiguration():
    initialize_configuration = False
    # call(["cp", "-v", "./{}".format(NAME_OF_SCRIPT), "{}".format(COPY_FILE_TO)])
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

    if not os.path.isfile(FILE_ALL_PROCESS_PID_WAITING):
        writeInJsonFile({}, json_file=FILE_ALL_PROCESS_PID_WAITING)
        initialize_configuration = True

    user_uid = os.geteuid()
    if user_uid == 0:
        createUserForExeAuthorization()
    else:
        user_name = pwd.getpwuid(user_uid).pw_name
        print("user_name ==> {}".format(user_name))
        addUserInJson(user_name)

    return initialize_configuration

def createUserForExeAuthorization():
    for user in pwd.getpwall():
        supposed_normal_user = int(user.pw_uid)
        if supposed_normal_user >= 1000 and supposed_normal_user <= 60000:
            print("createUserForExeAuthorization ==> ", user.pw_name)
            # user_exe_authorization[user.pw_name] = {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}
            addUserInJson(user.pw_name, json_file=FILE_USER_EXE_AUTHORIZATION)


def putFiableExeForUser(path_exe, authorization, type_of_authorization, user="all"):
    path_exe = os.path.abspath(path_exe)
    if os.path.exists(path_exe):
        if not os.path.isdir(path_exe):
            reformate_without_filename = hashExeSha256(path_exe)
            # print("sha_sum ==> {}".format(reformate_without_filename))
            all_sha256_exe = readFromFile(json_file=FILE_HASH_EXE)
            all_sha256_exe[path_exe] = reformate_without_filename
            writeInJsonFile(all_sha256_exe, json_file=FILE_HASH_EXE)
        user_exe_authorization = readFromFile(json_file=FILE_USER_EXE_AUTHORIZATION)
        if not (path_exe in user_exe_authorization[user][authorization][type_of_authorization]):
            user_exe_authorization[user][authorization][type_of_authorization].append(path_exe)
            writeInJsonFile(user_exe_authorization)

def findPathInAuthorization(list_of_paths, path_to_find):
    for lop in list_of_paths:
        if lop in path_to_find:
            return lop
    return None


def authorizationForUser(path_exe, user, type_of_authorization):
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
        # if user_exe_authorization[user][DENY_EXE][type_of_authorization] in path_exe:
        #     return DENY_EXE, user_exe_authorization[user][DENY_EXE][type_of_authorization]
        # if user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization] in path_exe:
        #     return ALWAYS_ASK_EXE, user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization]
        # if  user_exe_authorization[user][ALLOW_EXE][type_of_authorization] in path_exe:
        #     return ALLOW_EXE, user_exe_authorization[user][ALLOW_EXE][type_of_authorization]
    return None


def getAuthorizedShaForUser(path_exe, user, type_of_authorization):
    all_user = authorizationForUser(path_exe, "all", type_of_authorization)
    if all_user != None:
        return all_user
    specific_user = authorizationForUser(path_exe, user, type_of_authorization)
    if specific_user != None:
        return specific_user
    return None


def manageAuthorizationExecutionForUser(path_exe, user):
    get_authorization_hash_user_path = getAuthorizedShaForUser(path_exe, user, PATH_TO_PROCESS_EXE)
    # print("get_authorization_hash_user_path --> {}".format(get_authorization_hash_user_path))
    if get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == DENY_EXE:
        print("Deny path : {}".format(get_authorization_hash_user_path[1]))
        return KILL_IT, get_authorization_hash_user_path

    get_authorization_hash_user_process = getAuthorizedShaForUser(path_exe, user, PROCESS_EXE)
    hash_exe = hashExeSha256(path_exe)
    # print("get_authorization_hash_user_process --->\n{}\n{}\n{}".format(path_exe, get_authorization_hash_user_process, hash_exe))

    if get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == DENY_EXE and get_authorization_hash_user_process[1] == hash_exe:
        print("Deny process : {}".format(get_authorization_hash_user_process[1]))
        return KILL_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == ALLOW_EXE and get_authorization_hash_user_process[1] == hash_exe:
        # print("Allow process : {}".format(get_authorization_hash_user_process[1]))
        return ALLOW_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == ALLOW_EXE:
        # print("Allow path {}".format(get_authorization_hash_user_path[1]))
        return ALLOW_IT, get_authorization_hash_user_process
        
    return ASK_THEM, get_authorization_hash_user_process


def manageProcessAuthorizationExe(path_exe, type_of_authorization, user, authorization_exe=""):
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
    path_exe = os.path.abspath(path_exe)
    # if (type_of_authorization == PROCESS_EXE and not os.path.isfile(path_exe)) or (type_of_authorization == PATH_TO_PROCESS_EXE and not os.path.isdir(path_exe)):
    #     return NOT_EXISTS
    type_of_authorization = ""
    if os.path.isfile(path_exe):
        type_of_authorization = PROCESS_EXE
    elif os.path.isdir(path_exe):
        type_of_authorization = PATH_TO_PROCESS_EXE
    else:
        return NOT_EXISTS
    manage_process = manageAuthorizationExecutionForUser(path_exe, user)
    # print("manage_process ==> {}".format(manage_process))
    if manage_process[0] == ASK_THEM:
        authorization_exe = ""
        while(authorization_exe != "acc" and authorization_exe != "den" and authorization_exe != "ask"):
            authorization_exe = manageProcessAuthorizationExe(path_exe, type_of_authorization, user, authorization_exe=authorization_exe_decision)
            manage_process = manageAuthorizationExecutionForUser(path_exe, user)
            # print("Decision process action : {}".format(authorization_exe))
    return manage_process


# def processAuthorizationCli(process):


# PROCESS_EXE, PATH_TO_PROCESS_EXE

# Test pour les processes (acc, den, ask)
# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))

# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))

# main_process_authorization =  mainProcessAuthorizationExe("/home/gespenst/test_process_c", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))

# main_process_authorization =  mainProcessAuthorizationExe("/home/../../home/gespenst/", "gespenst")
# print("main_process_authorization ==> {}".format(main_process_authorization))
# print("all_sha256_exe ===> {}\n".format(all_sha256_exe))

'''
createUserForExeAuthorization()
print("user_exe_authorization ==> {}".format(user_exe_authorization))

putFiableExeForUser("/usr/bin/python2.7", "allow", PROCESS_EXE)
get_fiable_path = getAuthorizedShaForUser("/usr/bin/python2.7", "gespenst", PROCESS_EXE)
print("get_fiable_path ==> {}\n".format(get_fiable_path))

putFiableExeForUser("/usr/bin/sleep", "allow", PROCESS_EXE, user="gespenst")
get_fiable_path = getAuthorizedShaForUser("/usr/bin/sleep", "gespenst", PROCESS_EXE)
print("Sleep for gespenst ==> {}\n".format(get_fiable_path))

get_fiable_path = getAuthorizedShaForUser("/usr/bin/sleep", "all", PROCESS_EXE)
print("Sleep for all ==> {}\n".format(get_fiable_path))

print("user_exe_authorization ==> {}".format(user_exe_authorization))
'''


# {
#     'all': {
#         'allow': {
#             'PROCESS': ['/usr/bin/python2.7'], 'PATH_EXE_PROCESS': []
#         }, 
#         'deny': {
#             'PROCESS': [], 'PATH_EXE_PROCESS': []
#         }, 
#         'always_ask': {
#             'PROCESS': [], 'PATH_EXE_PROCESS': []
#         }
#     }, 
#     'gespenst': {
#         'allow': {
#             'PROCESS': ['/usr/bin/sleep'], 'PATH_EXE_PROCESS': []
#         }, 
#         'deny': {
#             'PROCESS': [], 'PATH_EXE_PROCESS': []
#         }, 
#         'always_ask': {
#             'PROCESS': [], 'PATH_EXE_PROCESS': []
#         }
#     }
# }

'''
cdq, cbw, cbd ---> https://www.abatchy.com/2017/04/shellcode-reduction-tips-x86
'''