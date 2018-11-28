#!/usr/bin/env python3

import crypt

def check_encryption_type(encryption_indicator):

    encryption_type = None

    if encryption_indicator == "$1$":
        encryption_type = 'MD5'
    elif encryption_indicator == "$2a$":
        encryption_type = 'Blowfish'
    elif encryption_indicator == "$2y$":
        encryption_type = 'Blowfish'
    elif encryption_indicator == "$5$":
        encryption_type = 'SHA-256'
    elif encryption_indicator == "$6$":
        encryption_type = 'SHA-512'
    else:
        encryption_type = None

    return encryption_type

def crack():
    shadow_file = open('/etc/shadow', 'r')

    for line in shadow_file.readlines():
        print("[+] Processing entry in shadow file: {}".format(line))

        hash_split = line.split(':')
        user = hash_split[0]
        print("[+] Trying to crack user: {}".format(user))

        full_hash = hash_split[1]
        print("[+] Full hash found: {}".format(full_hash))

        salt = full_hash[0:12]
        print("[+] Salt found: {}".format(salt))

        encryption_indicator = salt[:3]
        encryption_type = check_encryption_type(encryption_indicator)

        if not encryption_type:
            print("Couldn't determine encryption type, skipping....")
            continue
            

        print("[+] Attempting to crack {} encrypted password....".format(encryption_type))

        with open('passwords.txt') as wordlist:
            for word in wordlist:
                computed_hash = crypt.crypt(word.strip(), salt) 

                if (computed_hash == full_hash):
                    print("[!!!] Successfully cracked {} with password {}".format(user, word))
                    return

        print ("[x] Couldn't crack user {}\n\n\n".format(user))
                
if __name__ == '__main__':
    print("==============================================")
    print("====  ====  ==== ==== ==== ==== ==== ==== ====")
    print(" ==    ==    ==   ==   ==   ==   ==   ==   ==")
    print(" x     x     x    x     x    x    x    x    x")
    print("----------------CRACKER JACKER---------------")

    input("\n\n        PRESS ANY KEY TO BEGIN       \n\n")

    crack()
