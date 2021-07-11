import os

# Permet au format des données JSON
ALLOW_EXE = "allow" # autorise l'execution d'un processus
DENY_EXE = "deny" # refuser l'execution d'un processus
ALWAYS_ASK_EXE = "always_ask" # pas encore implémenté mais est censé toujours demandé l'execution d'un programme.

# Type d'autorisation 
PROCESS_EXE = "PROCESS" # autoriser un fichier
PATH_TO_PROCESS_EXE = "PATH_EXE_PROCESS" # autoriser un dossier

# "Enumération" permettant de gérer les processus trouvés.
NOT_EXISTS = -2
KILL_IT = -1
ASK_THEM = 0
ALLOW_IT = 1

# Nombre de boucle avant le "blacklist" automatique du processus 
NBR_WAIT_FOR_ACTION = 24

# fichier du CRON qui permet de gérer les processus
NAME_OF_SCRIPT = os.path.basename(__file__)
COPY_FILE_TO = "."

# Dossier permettant le stockage des données JSON 
FOLDER_SAVING_EVENT = os.environ["HOME"]+"/PROJECT_PYTHON_WITH_NO_NAME"

# regroupe en format JSON, les fichiers et dossiers qui sont "allow" ou "deny" pour executer des processus.
FILE_USER_EXE_AUTHORIZATION = FOLDER_SAVING_EVENT+"/AUTHORIZATION_EXE.json"

# Regroupe tous les hash des fichiers demandés. 
FILE_HASH_EXE = FOLDER_SAVING_EVENT+"/FILE_HASH_EXE.json"

# fichier temporaire regroupant une action requise pour un utilisateur.
FILE_ALL_PROCESS_PID_WAITING = FOLDER_SAVING_EVENT+"/all_process_tmp.json"