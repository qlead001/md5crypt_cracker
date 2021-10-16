import re
import os
import sys
import os.path

MAGIC = '1'
SHADOW = 'etc_shadow'
SHADOW_ALT = 'shadow'
OUT_FILE = 'cracked_passwords.txt'

pass_re = re.compile(r'Password: (\S+), Hash: ([0-9a-zA-Z./]{22})')
hash_re = re.compile(r'([0-9a-zA-Z./]{22}) \| (\S+)')

def atoi(text):
        return int(text) if text.isdigit() else text

def natural_keys(text):
    return [ atoi(c) for c in re.split(r'(\d+)', text) ]

def get_logs():
    files = []

    with os.scandir() as it:
        for entry in it:
            if entry.is_file() and entry.name.endswith('.log'):
                files.append(entry.name)

    return files

def read_log(log):
    salt = log.split('_')[0]
    passwords = {}

    with open(log) as f:
        text = f.read()

    for passwd, hash in pass_re.findall(text):
        passwords[f'${MAGIC}${salt}${hash}'] = passwd

    for hash, passwd in hash_re.findall(text):
        full_hash = f'${MAGIC}${salt}${hash}'

        if full_hash not in passwords:
            passwords[full_hash] = passwd
        elif passwd != passwords[full_hash]:
            print('Error: Found two different passwords for same hash '
                  f'in {log}', file=os.stderr)
            print(f'\tHash: {hash}', file=os.stderr)
            print(f'\tPasswords: {passwords[full_hash]}', file=os.stderr)
            print(f'\t           {passwords[full_hash]}', file=os.stderr)
            sys.exit(1)

    return passwords

def read_shadow():
    users = {}

    if os.path.exists(SHADOW):
        with open(SHADOW) as f:
            for line in f:
                user, hash, _ = line.split(':', 2)
                users[hash] = user

    if os.path.exists(SHADOW_ALT):
        with open(SHADOW_ALT) as f:
            for line in f:
                user, hash, _ = line.split(':', 2)
                users[hash] = user

    return users

def get_cracked():
    data = []
    if os.path.exists(OUT_FILE):
        with open(OUT_FILE, 'r') as f:
            header = f.readline().rstrip().split(':')
            user_col = header.index('user')
            hash_col = header.index('hash')
            pass_col = header.index('password')

            for line in f:
                vals = line.rstrip().split(':')
                data.append((vals[user_col], vals[hash_col], vals[pass_col]))

    return data

def main():
    users = read_shadow()
    data = get_cracked()
    passwords = {}
    pass_count = 0

    for log in get_logs():
        passwords.update(read_log(log))

    for hash, passwd in passwords.items():
        user = users.get(hash, '')
        if (user, hash, passwd) not in data:
            data.append((user, hash, passwd))
            pass_count += 1

    data.sort(key=lambda x: x[2])
    data.sort(key=lambda x: x[1])
    data.sort(key=lambda x: natural_keys(x[0]))

    with open(OUT_FILE, 'w') as f:
        f.write(f'user:hash:password\n')

        for user, hash, passwd in data:
            f.write(f'{user}:{hash}:{passwd}\n')

    print(f'Added {pass_count} passwords to {OUT_FILE}')

if __name__ == "__main__":
        main()
