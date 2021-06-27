import json
import os
import pwd
import shutil
from subprocess import call, Popen, PIPE, check_output

# USER_AUTHORIZATION_PROCESS = "USER_AUTHORIZATION_PROCESS"
# SHA_PROCESS = "SHA_PROCESS"

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

# print("pwd.getpwall() --> {}".format(pwd.getpwnam("gespenst").pw_dir))
# print(os) # getpid(), getppid()
# print("geteuid --> ", os.geteuid())
# print("geteuid --> ", os.environ["HOME"])

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
    json_file_read = open(json_file, "r")
    data_from_file = json.load(json_file_read)
    json_file_read.close()
    return data_from_file


def writeInJsonFile(data_json, json_file=FILE_USER_EXE_AUTHORIZATION):
    json_file_write = open(json_file, "w")
    json_file_write.write(json.dumps(data_json))
    json_file_write.close()
    return True

def addUserInJson(json_file=FILE_USER_EXE_AUTHORIZATION):
    try:
        read_folder = readFromFile()
        for rf in read_folder:
            print("rf --> {}".format(rf))
    except KeyError as k:
        print("[createFolderForSave] Error: {}".format(k))
        return None

def initializeAllConfiguration():
    # call(["cp", "-v", "./{}".format(NAME_OF_SCRIPT), "{}".format(COPY_FILE_TO)])
    shutil.copy2(NAME_OF_SCRIPT, COPY_FILE_TO)

    if not os.path.isdir(FOLDER_SAVING_EVENT):
        createFolderForSave()

    if not os.path.isfile(FILE_USER_EXE_AUTHORIZATION):
        user_exe_authorization = {"all": {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}}
        writeInJsonFile(user_exe_authorization)

    if not os.path.isfile(FILE_HASH_EXE):
        destination_file = COPY_FILE_TO + "/" + NAME_OF_SCRIPT
        hash_exe = hashExeSha256(destination_file)
        all_sha256_exe = {destination_file : hash_exe}
        writeInJsonFile(all_sha256_exe, json_file=FILE_HASH_EXE)

# createFolderForSave("gespenst")
# addUserInJson()
# initializeAllConfiguration()
exit(1)

# user_exe_authorization = {"all": {ALLOW_EXE : [], DENY_EXE : [], ALWAYS_ASK_EXE: []}}
user_exe_authorization = {"all": {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}}

# Regroupe une pair (chemin complet vers un fichier, son hash en sha256)
all_sha256_exe = {}

def hashExeSha256(path_exe):
    path_exe = os.path.abspath(path_exe)
    sha256sum = Popen(('sha256sum', path_exe), stdout=PIPE)
    reformate_without_filename = check_output(('cut', '-d', ' ', '-f', '1'), stdin=sha256sum.stdout).decode("latin").strip()
    sha256sum.wait()
    return reformate_without_filename


def createUserForExeAuthorization():
    for user in pwd.getpwall():
        supposed_normal_user = int(user.pw_uid)
        if supposed_normal_user >= 1000 and supposed_normal_user <= 60000:
            print("createUserForExeAuthorization ==> ", user.pw_name)
            user_exe_authorization[user.pw_name] = {ALLOW_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, DENY_EXE : {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}, ALWAYS_ASK_EXE: {PROCESS_EXE: [], PATH_TO_PROCESS_EXE: []}}


def putFiableExeForUser(path_exe, authorization, type_of_authorization, user="all"):
    path_exe = os.path.abspath(path_exe)
    if os.path.exists(path_exe):
        if not os.path.isdir(path_exe):
            reformate_without_filename = hashExeSha256(path_exe)
            print("sha_sum ==> {}".format(reformate_without_filename))
            all_sha256_exe[path_exe] = reformate_without_filename
        # print("putFiableExeForUser ==> {} - {} - {}\n".format(path_exe, authorization, user))
        if not (path_exe in user_exe_authorization[user][authorization][type_of_authorization]):
            user_exe_authorization[user][authorization][type_of_authorization].append(path_exe)


def authorizationForUser(path_exe, user, type_of_authorization):
    if type_of_authorization == PROCESS_EXE or type_of_authorization == PATH_TO_PROCESS_EXE:
        if path_exe in user_exe_authorization[user][DENY_EXE][type_of_authorization]:
            return DENY_EXE, all_sha256_exe[path_exe] if type_of_authorization == PROCESS_EXE else user_exe_authorization[user][DENY_EXE][type_of_authorization]
        if path_exe in user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization]:
            return ALWAYS_ASK_EXE, all_sha256_exe[path_exe] if type_of_authorization == PROCESS_EXE else user_exe_authorization[user][ALWAYS_ASK_EXE][type_of_authorization]
        if path_exe in user_exe_authorization[user][ALLOW_EXE][type_of_authorization]:
            return ALLOW_EXE, all_sha256_exe[path_exe] if type_of_authorization == PROCESS_EXE else user_exe_authorization[user][ALLOW_EXE][type_of_authorization]
    return None


def getAuthorizedShaForUser(path_exe, user, type_of_authorization):
    # if path_exe in all_sha256_exe:
    all_user = authorizationForUser(path_exe, "all", type_of_authorization)
    print("all_user ==> {}".format(all_user))
    if all_user != None:
        return all_user
    specific_user = authorizationForUser(path_exe, user, type_of_authorization)
    print("specific_user ==> {}".format(specific_user))
    if specific_user != None:
        return specific_user
    # elif type_of_authorization == PATH_TO_PROCESS_EXE:

    return None


def manageAuthorizationExecutionForUser(path_exe, user):
    get_authorization_hash_user_path = getAuthorizedShaForUser(path_exe, user, PATH_TO_PROCESS_EXE)
    print("get_authorization_hash_user_path ==> {}".format(get_authorization_hash_user_path))
    if get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == DENY_EXE:
        print("Deny path : {}".format(get_authorization_hash_user_path[1]))
        return KILL_IT, get_authorization_hash_user_path

    get_authorization_hash_user_process = getAuthorizedShaForUser(path_exe, user, PROCESS_EXE)
    hash_exe = hashExeSha256(path_exe)

    if get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == DENY_EXE and get_authorization_hash_user_process[1] == hash_exe:
        print("Deny process : {}".format(get_authorization_hash_user_process[1]))
        return KILL_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_process != None and get_authorization_hash_user_process[0] == ALLOW_EXE and get_authorization_hash_user_process[1] == hash_exe:
        print("Allow process : {}".format(get_authorization_hash_user_process[1]))
        return ALLOW_IT, get_authorization_hash_user_process
    elif get_authorization_hash_user_path != None and get_authorization_hash_user_path[0] == ALLOW_EXE:
        print("Allow path {}".format(get_authorization_hash_user_path[1]))
        return ALLOW_IT, get_authorization_hash_user_process
        
    return ASK_THEM, get_authorization_hash_user_process


def manageProcessAuthorizationExe(path_exe, type_of_authorization, user):
    authorization_exe = input("Accepter, refuser ou toujours demander l'autorisation d'utiliser le binaire '{}' [acc/den/ask] ? ".format(path_exe))
    if authorization_exe == "acc":
        putFiableExeForUser(path_exe, ALLOW_EXE, type_of_authorization, user=user)
    elif authorization_exe == "den":
        putFiableExeForUser(path_exe, DENY_EXE, type_of_authorization, user=user)
    elif authorization_exe == "ask":
        putFiableExeForUser(path_exe, ALWAYS_ASK_EXE, type_of_authorization, user=user)
    return authorization_exe


def mainProcessAuthorizationExe(path_exe, user, type_of_authorization):
    path_exe = os.path.abspath(path_exe)
    print("\npath_exe ==> {}\n".format(path_exe))
    if (type_of_authorization == PROCESS_EXE and not os.path.isfile(path_exe)) or (type_of_authorization == PATH_TO_PROCESS_EXE and not os.path.isdir(path_exe)):
        return NOT_EXISTS
        
    manage_process = manageAuthorizationExecutionForUser(path_exe, user)
    print("manage_process ==> {}".format(manage_process))
    if manage_process[0] == ASK_THEM:
        authorization_exe = ""
        while(authorization_exe != "acc" and authorization_exe != "den" and authorization_exe != "ask"):
            authorization_exe = manageProcessAuthorizationExe(path_exe, type_of_authorization, user)
    print("[mainProcessAuthorizationExe] user_exe_authorization ==> {}".format(user_exe_authorization))
    return manage_process


# PROCESS_EXE, PATH_TO_PROCESS_EXE

createUserForExeAuthorization()
print("user_exe_authorization ==> {}".format(user_exe_authorization))

# Test pour les processes (acc, den, ask)
# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst", PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))

# main_process_authorization =  mainProcessAuthorizationExe("/usr/bin/python2.7", "gespenst", PROCESS_EXE)
# print("main_process_authorization ==> {}".format(main_process_authorization))

main_process_authorization =  mainProcessAuthorizationExe("/home/gespenst/", "gespenst", PATH_TO_PROCESS_EXE)
print("main_process_authorization ==> {}".format(main_process_authorization))

main_process_authorization =  mainProcessAuthorizationExe("/home/../../home/gespenst/", "gespenst", PATH_TO_PROCESS_EXE)
print("main_process_authorization ==> {}".format(main_process_authorization))
print("all_sha256_exe ===> {}\n".format(all_sha256_exe))

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


'''
    - test.py (--), test1.py (++)
    python test.py --->
'''