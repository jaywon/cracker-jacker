#!/usr/bin/env python3
import os.path
import crypt
import argparse

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

def crack(wordlist_path, shadowfile_path):
    shadow_file = open(shadowfile_path, 'r')

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

        with open(wordlist_path) as wordlist:
            for word in wordlist:
                computed_hash = crypt.crypt(word.strip(), salt) 

                if (computed_hash == full_hash):
                    print("[!!!] Successfully cracked {} with password {}".format(user, word))
                    return

        print ("[x] Couldn't crack user {}\n\n\n".format(user))
                
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                prog="Cracker Jacker",
                description="Command line tool to brute force crack /etc/shadow with a wordlist")

    parser.add_argument('--wordlist', '-w', required=True, help='Filepath of wordlist to use')
    parser.add_argument('--shadowfile', '-s', help='Filepath to shadow file', default='/etc/shadow')

    args = parser.parse_args()

    if not os.path.exists(args.wordlist) or not os.path.isfile(args.wordlist):
        print("Doh!!! Invalid wordlist path bruh...")
        quit()

    if not os.path.exists(args.shadowfile) or not os.path.isfile(args.shadowfile):
        print("Doh!!! Invalid shadowfile path bruh...")
        quit()

    print("==============================================")
    print("====  ====  ==== ==== ==== ==== ==== ==== ====")
    print(" ==    ==    ==   ==   ==   ==   ==   ==   ==")
    print(" x     x     x    x     x    x    x    x    x")
    print("----------------CRACKER JACKER---------------")

    input("\n\n        PRESS ANY KEY TO BEGIN       \n\n")

    crack(args.wordlist, args.shadowfile)

