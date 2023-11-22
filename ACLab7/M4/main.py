
array = [b'a', b'a 23 bytes long string', b'64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']

res = ""
for s in array:
    AL = int.to_bytes(len(s)*8, 8, 'big', signed=False)
    print(AL.hex())

