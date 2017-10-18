import itertools
import rsa
from Crypto.PublicKey import RSA


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def get_pubkeys():
    # Using rsa module to read public key
   keys = {}
   print "\n********** Key List Start **********"
   for i in range (1,12):
       try:
           fp = open('public' + str(i) + '.pub')
           key = RSA.importKey(fp.read()) 
           keys[fp] = key
           print str(i) + "  :  " + str(key)
       except IOError:
           print "Read file error..."
           break

   print "********** Key List End **********\n"
   return keys


def find_common_key():
    # Find the potential common public key in current folder
    pubkeys = get_pubkeys()

    for p1, p2 in itertools.permutations(pubkeys, 2):
        g = gcd(pubkeys[p1].n, pubkeys[p2].n)
        if g != 1:
            yield (p1, pubkeys[p1]), (p2, pubkeys[p2]), g


def generate_private_key(pubkey, q):
    p = pubkey.n // q
    e, d = rsa.key.calculate_keys_custom_exponent(p, q, pubkey.e)

    return rsa.PrivateKey(pubkey.n, e, d, p, q)


def save_private_key(priv, name):
    private_key_name = name.name.replace('public', 'private').replace('.pub', '.pem')
    f = open(private_key_name, 'wb')
    f.write(priv.save_pkcs1())
    print private_key_name


def verify_key(pub, priv):
    text = 'This is plain text.'.encode('utf-8')
    try:
        assert rsa.decrypt(rsa.encrypt(text, pub), priv) == text
    except ValueError:
        print "Private key went wrong..."
        

if __name__ == '__main__':
    print('Step 1: Find common factor key')
    used_keys = set()
    for pub1, pub2, g in find_common_key():
        if pub1[0] in used_keys or pub2[0] in used_keys:
            continue
        used_keys.add(pub1[0])
        used_keys.add(pub2[0])

        print('Step 2: Generate private keys')
        priv1 = generate_private_key(pub1[1], g)
        priv2 = generate_private_key(pub2[1], g)

        print('Step 3: Save private keys')
        save_private_key(priv1, pub1[0])
        save_private_key(priv2, pub2[0])

        print('Step 4: Verify public/private keys')
        verify_key(pub1[1], priv1)
        verify_key(pub2[1], priv2)
        
        print("Verify Done!!\n")