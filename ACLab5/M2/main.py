import hashlib

f = open("/Users/alecabodi/PycharmProjects/ACLab5/M2/rockyou.txt", "r", errors='replace')
lines = f.readlines()
for l in lines:
    pw = l.encode().strip(b'\n')
    if hashlib.md5(pw).hexdigest() == '9fb7009f8a9b4bc598b4c92c91f43a2c':
        print(pw)
        break
