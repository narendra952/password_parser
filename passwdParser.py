import json
import argparse
import os.path

"""constant template values for passwd file
"""
MAX_FIELDS_IN_A_LINE_PASSWD_FILE = 7
USER_NAME_INDEX = 0
USER_ID_INDEX = 2
USER_GROUP_ID_INDEX = 3
USER_GECOS_INDEX = 4
USER_HOME_DIRECTORY_PATH_INDEX = 5
USER_LOGIN_SHELL_PATH_INDEX = 6

"""constant template values for group file
"""
MAX_FIELDS_IN_A_LINE_GROUP_FILE = 4
GROUP_NAME_INDEX = 0
GROUP_ID_INDEX = 2
GROUP_USERS_INDEX = 3

"""constant template values for merged json file
"""
UID = 'uid'
FULL_NAME = 'full_name'
GROUPS = 'groups'


def checkFileValidity(fname):
    if not os.path.exists(fname):
        sys.exit("{}: {}".format("IOError", 'Can\'t find file %s' % (fname)))
    if not os.access(fname, os.R_OK):
        sys.exit("{}: {}".format("IOError", 'Permission denied to read file %s' % (fname)))
    return fname


""" 1. The below function checks if each line in passwd file is as per standard format 
    2. Code for User home directory path existence and user login shell path existence is also supported,
        but os.path.isdir is not working in my laptop. So commented it
"""
def checkValidityOfLineInPasswdFile(passwdData, distinctGroupIDs, distinctUserIds, distinctUserNames):
    """check if number of fields in a line are MAX_FIELDS_IN_A_LINE_PASSWD_FILE_FILE(4) """
    if len(passwdData) != MAX_FIELDS_IN_A_LINE_PASSWD_FILE:
        raise Exception("Number of fields in a line of '{}' file are not as per standards".format(args.groupPath))
#     if not os.path.isdir(os.path.join('/', passwdData[USER_HOME_DIRECTORY_PATH_INDEX].rstrip())):
#         raise Exception("User Home Directory does not exist")
#     if not os.path.isdir(os.path.join('/', passwdData[USER_LOGIN_SHELL_PATH_INDEX].rstrip())):
#         raise Exception("Valid User login shell does not exist for user '{}'".format(passwdData[USER_NAME_INDEX]))
    if passwdData[USER_GROUP_ID_INDEX] not in distinctGroupIDs:
        raise Exception("InValid User's group Id which does not exist in group file")
    if passwdData[USER_NAME_INDEX] in distinctUserNames:
        raise Exception("Single userName detected in multiple lines of '{}' file which is not as per standards".format(args.passwdPath))
    if passwdData[USER_ID_INDEX] in distinctUserNames:
        raise Exception("Single user Id assigned to different users in '{}' file which is not as per standards".format(args.passwdPath))
                        

""" The below function checks if each line in group file is as per standard format 
"""
def checkValidityOfLineInGroupFile(groupData, distinctGroupIDs, distinctGroupNames):
    """
    check if number of fields in a line are MAX_FIELDS_IN_A_LINE_GROUP_FILE(7)
    """
    if len(groupData) != MAX_FIELDS_IN_A_LINE_GROUP_FILE:
        raise Exception("Number of fields in a line of '{}' file are not as per standards".format(args.groupPath))
    if groupData[GROUP_ID_INDEX] in distinctGroupIDs:
        raise Exception("Multiple lines with same group IDs in '{}' file which is not as per standards".format(args.groupPath))
    if groupData[GROUP_NAME_INDEX] in distinctGroupNames:
        raise Exception("Multiple lines with same group names in '{}' file which is not as per standards".format(args.groupPath))
  

    
""" The below function parses the passwd file to get the users mapped to corresponding groups 
"""
def parsePasswdFile(fname, distinctGroupIDs, usersGroupMap):
    with open(fname, 'r') as file:
        distinctUserIds = set()
        distinctUserNames = set()
        userMappedToGroups = dict() 
        """    'list' -> { "uid": "38",
                            "full_name": "Mailing List Manager",
                            "groups": []
                        }
        """
        for line in file:
            line = line.rstrip()
            passwdData = line.split(":")
            checkValidityOfLineInPasswdFile(passwdData, distinctGroupIDs, distinctUserIds, distinctUserNames)
            distinctUserIds.add(passwdData[USER_ID_INDEX])
            distinctUserNames.add(passwdData[USER_NAME_INDEX])
            userValues = dict()
            userValues[UID] = passwdData[USER_ID_INDEX]
            userValues[FULL_NAME] = passwdData[USER_GECOS_INDEX].split(',')[0]
            if passwdData[USER_NAME_INDEX] in usersGroupMap: 
                userValues[GROUPS] = usersGroupMap[passwdData[USER_NAME_INDEX]]
            else:
                userValues[GROUPS] = {}
            userMappedToGroups[passwdData[USER_NAME_INDEX]] = userValues
    return userMappedToGroups        
    
    
""" The below function parses the group file to get the users who are in atleast one group 
"""
def parseGroupFile(fname, distinctGroupIDs):
    with open(fname, 'r') as file:
        distinctGroupNames = set() # 'group_1', 'group_2' 
        groups = dict() 
        """ { '1'->('group_1','group_2')
                '2'->('group_1','group_3','group_5')}  
        """
        for line in file:
            line = line.rstrip()
            groupData = line.split(":")
            checkValidityOfLineInGroupFile(groupData, distinctGroupIDs, distinctGroupNames)
            distinctGroupNames.add(groupData[GROUP_NAME_INDEX])
            distinctGroupIDs[groupData[GROUP_ID_INDEX]] = groupData[GROUP_NAME_INDEX]
            userList =  groupData[GROUP_USERS_INDEX].split(',') 
            """taking first value in GECOS which corresponds to full name
                Source: https://en.wikipedia.org/wiki/Gecos_field
            """ 
            if len(groupData[GROUP_USERS_INDEX]) < 2:
                continue
            for user in userList:
                if user not in groups:
                    groups[user] = []
                groups[user].append(groupData[GROUP_NAME_INDEX])  
                """ Assumed group name and user name can be same
                """
    return groups

parser = argparse.ArgumentParser(description="Parse the UNIX /etc/passwd and /etc/group files and combine the data into a single json output")
parser.add_argument("-p", "--passwd", type=str, dest="passwdPath",
                    default="/etc/passwd", help="passwd file path")
parser.add_argument("-g", "--group", type=str, dest="groupPath",
                    default="/etc/group", help="group file path")
parser.add_argument("-o", "--outputfile", type=str, dest="outputJsonPath",
                    default="UsersData.json", help="output Json file path")

args = parser.parse_args(args=[]) #change this line

checkFileValidity(args.passwdPath)
checkFileValidity(args.groupPath)

distinctGroupIDs = {} # '1'->'group_1', '2'->'group_2'

"""parse group file to generate user->groups mapping (usersGroupMap)
For example:
    ubuntu -> ['adm','cdrom','sudo']
    narendra -> ['audio']
"""
usersGroupMap = parseGroupFile(args.groupPath, distinctGroupIDs)


"""parse passwd file to get completeUserInfo
For example:
    for a single user, 
    'list' -> { "uid": "38",
                  "full_name": "Mailing List Manager",
                  "groups": []
                 }
"""
completeUserInfo = parsePasswdFile(args.passwdPath, distinctGroupIDs, usersGroupMap)

with open(args.outputJsonPath, 'w') as outfile:
    json.dump(completeUserInfo, outfile, indent=4)




