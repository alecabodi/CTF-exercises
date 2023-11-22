# ex 1
import hashlib

print(hashlib.sha224(b"you made it").hexdigest())

# ex 2
from Crypto.Hash import SHA256

print(SHA256.new(data=b'hi').hexdigest())

# ex 3
from Crypto.Hash import SHA256

array = b'LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUteni' \
        b'madminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinrep' \
        b'rehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs.'

blocks = [array[i:i + 16] for i in range(0, len(array), 16)]

v = b''
for b in blocks:
    v += b[15].to_bytes(1, 'big')

print(SHA256.new(data=v).hexdigest())

# ex 4
array = '596f752063616e206465636f646521'
array = bytes.fromhex(array)
print(array)

# ex 5
string = "ጷ뼯쯾"
print(string.encode().hex())

# ex 6
array = bytes.fromhex('210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002')

for key in range(256):
    res = bytes(x ^ key for x in array)
    print(res)

# ex 7
string = "Pay no mind to the distant thunder, Beauty fills his head with wonder, boy"
X = bytes.fromhex(string.encode().hex())

Y = bytes.fromhex(
    'bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f4'
    '89f3454bbe1cab4510ccb979013277a7bf')
res = bytes(x ^ y for (x, y) in zip(X, Y))
print(res.hex())


# ex 8
from itertools import cycle


def xor(a, b):
    if len(a) < len(b):
        a, b = b, a
    return bytes([i ^ j for i, j in zip(a, cycle(b))])


ciphertext1 = bytes.fromhex(
    '9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0')
ciphertext2 = bytes.fromhex(
    'b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83'
    'e4')

xor_c = xor(ciphertext1, ciphertext2)

guess1 = b"flag{"
for i in range(len(xor_c)):
    guess1 += b'0'

res_tmp1 = xor(xor_c, guess1)
print(res_tmp1)

guess2 = b"flag{One time pad is perfectly secure, what can go wrong"
for i in range(len(xor_c)):
    guess1 += b'0'

res_tmp2 = xor(xor_c, guess2)
print(res_tmp2)


# ex 9
CHALLENGE_PLAINTEXT = bytes.fromhex(
    '4d68f21bf515dce57ee78a66724c4d9f5416fadc8d417652d8cbe1ce8080fc132bec643cc30460f9561669cc16d2786af846a12c611c6dc15'
    '0504a22b18c95c9e34dd8f0efb1aa0fe0ec8a996b03ee56b27bac5bbc70413a5fa29de92dfee2802735e334c44f026e6cbbf9b40f65a0faf3b'
    'f11ddfb75083b417eb306f317c4f07bf88c27714555994045a9c8cf517042dccaf4c98e82a50336bc7836911325ea4b107e8942ce752fb450b'
    'a29660024da43045725ba8c9fc0ea52d6e0eeebf940effd8a997c03e405bb70e25eb138153d5ca29cf22dfee6837e23ac2dc5161c723ebbbce'
    '71862b3bfeabb0698a86a097e0465a012ea0dc4ea73fb9b746409559f5953fa899a42224fc4dbb5c4869eb41530e86921c55729e01e1d3bca5'
    '9ca6562b646f86e650061c740044d6db6dfd4d1fb4099feefabbe5be9be80df281fe940f77ee940b23f473614a29cf22db0ad836637ab7fc25'
    '9197473b1f5f71a63e5b8fdfe16c6ed7f157e4026b318ba0dcde132f48b77784c4b82524efd898054225a8cd3fac9808fb0002afd6e3cc51e2'
    '3ae4d0679da42cf647aac5cbb20320b6dc54d415163ffcd8785e050dafaa6e5bc4ee2f6cfda6707f448b935ef58ab7057371ae39cee29bde68'
    '36374b436d55e55676cbaa4e11e63a6a3b8bf0cd5e46712725728f218f314cce873e58e7e3c094e9e5244ec898e127054d8d1e7879c9aae152'
    '3f12c3ad80728eb4c5376c855ce7961bd15bc2f614866d0404a0338acc99089b351d1fbf9e5b44af5f680dd2806e05cf774e055aa27152652e'
    '7c8fe2dbaf885733dac31815913216ab7b0b41768abbdecb642dbee3e0875406fa402fe0cc4e832e58d737f5b4ad81742e1cccf596348c5cdf'
    'ececf8ba4112ff56238c51e2fe01e1a75df59ca666aab15b8217d036ddb42044522ad8c87d1e14cd7f5f9e5b649a1fd87d87a0ae251b267ff1'
    '9b13854261ae39aff68ace8966235b73ac5161c6f3eabbdf15b6eacaaf0bb10c0ed6615350472ba0eba0ad1f67bf98574305a5199425aed898'
    'd57224fc4ccf0c2cf8db41130fd6f2dd40533ae521c75ce16c9622fb55aa62b320e6bc705504b28ffc98cc4fe4cd7f3feacb641a1ea80996a0'
    'ea156a276ef5cb623532756acc8ee20bbe3ca2720ab3a81521c726abebbf71e7ee5b8fdaa15d1ed7041784b68a10ef90cd1ed64f2c268734a4'
    'c844553e7ca8a412254ca9ee1cf8aceaf0430f5623ec25721fc5b5377c05dc37c76f841bb6e700d24d850485724afc091d6b34adfb2feadbc0'
    'fedfb81de7c03a14ab135f851a0705e3743f587e82cf0ad926f21b07fc75f1b6577b1b2b41662b7bfb8ac07c4ed7f157e4026a11fe810cbe36'
    '1b78c66625b56814416edc6985c224fc4dbb5d7809daf1920f06979dd122ee94a1b688959c0307bb050f425771173da57400f6dacc59ac6f60'
    '5cef7aaa6b841a1ea8ed26d4bf54db235eb4ba031413749f6c8f927b3e0896974a736d75f066e6cffbaf25b6ca9b6b8aa0ad1a87a08685067b'
    'c08ff0a8ba466ff8727624c58855858a9dd875b711bd8dbe6d3cf99b30229ef2c30c25734e65f073bc05086712faa50a42b731c61d10557573'
    'fb6c29385fc46dae7f8b6f946efbe9bd16d4bf149b67ce24da028417e1ae386fe68aae5832730aa2cd5571b627bffb7f10f7aa0bff6fe01dbf'
    'a6c04685469bc0ff317c2a471ff8375714a4d934545a9c09c12631bc1cbf9d3869eb01562f36a79c51f25ae551662de59d4742fb450ba29660'
    '02895514c466db4c98dd2fc57ddb2e6a0ad5be4ec9c997f02ed49f779e557a07040221aeb86ba3cb6e8c67435ae3a814114783ea8bce0132d'
    'a7b5ecb642dbeb7d14695663bc08ff0a85eb74b7966f75094a82455fe7cec1126457cdd9eec19d8bad0527f26f2091162eef520a68c045867'
    'f61f847b13e770970d041044828a6df80d7f644d4ef')

blocks = [CHALLENGE_PLAINTEXT[i:i + 120] for i in range(0, len(CHALLENGE_PLAINTEXT), 120)]
ok = b"abcdefghijklmnopqrstuvwxyz.,{} "

LEN = 68
CURR_KEY = b'$\x06\xd2k\x9ay\xa5\x84\x12\x97\xe2\x07\x10)9\xf676\x89\xa9\xef2\x02;\xac\xbe\x95\xa7\xef\xee\xdcpB\x9c' \
           b'\x0cY\xb1w@\x8e>s\x1b\xa96\xa6\x10\x0f\xd85\xd4N\x12h\x04\xb5%$#M\xdf\xac\xf4\xa5\x93'
RED_KEY = b'$\x06\xd2k\x9ay\xa5\x84\x12\x97\xe2\x07\x10)9\xf676\x89\xa9\xef2\x02;\xac\xbe\x95\xa7\xef'
RED_KEY2 = b'$\x06\xd2k\x9ay\xa5\x84\x12\x97\xe2\x07\x10)9\xf676\x89\xa9\xef2\x02;\xac\xbe\x95\xa7\xef\xee\xdcpB\x9c' \
           b'\x0cY\xb1w@\x8e>s\x1b\xa96\xa6\x10\x0f\xd85\xd4N\x12h\x04\xb5%$#M'

SIZE = 100000

final = dict()
for i in range(0, LEN):
    final.update({i: []})

for i in range(0, LEN):

    for key in range(0, 2 ** 8):

        flag = True
        res = b''
        for block in blocks:
            res = xor(block[i].to_bytes(1, 'big'), key.to_bytes(1, 'big'))

            if not all(c in ok for c in res):
                flag = False
                break

        if flag:
            final.get(i).append(key.to_bytes(1, 'big'))

print(final)

keys = []
for i in range(0, SIZE):
    keys.append(b'')

curr_size = 1
prev_size = 1
first = True
for i in range(len(final)):

    if i % 30 == 0 and not first:
        if i % 60 == 0:
            for j in range(curr_size):
                if not keys[j].__contains__(RED_KEY2):
                    keys[j] = b''
        else:
            for j in range(curr_size):
                if not keys[j].__contains__(RED_KEY):
                    keys[j] = b''

        keys = sorted(keys[0:curr_size], reverse=True) + keys[curr_size:]
        curr_size = 1
        prev_size = 1

    if i == 0:
        first = False

    tmp = final.get(i)
    if len(tmp) == 1:
        for j in range(curr_size):
            keys[j] += tmp[0]
    else:
        curr_size *= len(tmp)
        k = 0
        for j in range(prev_size, curr_size):
            keys[j] += keys[k]
            k = (k + 1) % prev_size

        keys = sorted(keys[0:curr_size]) + keys[curr_size:]

        k = 0
        for j in range(curr_size):
            keys[j] += tmp[k]
            k = (k + 1) % len(tmp)

        prev_size = curr_size

for i in range(curr_size):
    if keys[i].__contains__(CURR_KEY):
        print("\n")
        print("step " + str(i))
        print(b'CURR_KEY = ' + b'b\'' + keys[i] + b'\'')
        print("\n")
        for block in blocks:
            print(xor(block[0:LEN], keys[i]))
