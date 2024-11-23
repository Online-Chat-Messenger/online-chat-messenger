from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
print(public_key)
pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_key2 = serialization.load_pem_public_key(pem,backend=default_backend())
print(public_key == public_key2)





message = b"encrypted data"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)


plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(plaintext)
print(message)
































# import math

# def lcm(p,q):
#     return p*q // math.gcd(p,q)

# def rsa(p,q,text):
#     # ２つの素数p,qから秘密鍵と公開鍵を生成
#     N = p*q
#     L = lcm(p-1,q-1)
#     print(L)

#     # Lと互いに素かつ1 < E < Lとなる整数を求める
#     for i in range(2,L):
#         if math.gcd(i,L) == 1:
#             E = i
#             break
        
#     # 
#     for i in range(2,L):
#         if (E * i) % L == 1:
#             D = i
#             break

#     # public key
#     print((E,N))
#     intText = [ord(char) for char in text]
#     print("asiccText = "  + str(intText))
#     powText1 = [pow(i,E,N) for i in intText]
#     print("powResult =  " + str(powText1))
#     encryptedText = ''.join(chr(i) for i in powText1)
#     print("ET = " + encryptedText)

#     # private key
#     print((D,N))
#     EText = [ord(char) for char in encryptedText]
#     print("EInt = " + str(EText))
#     powText2 = [pow(i,D,N) for i in EText]
#     print("powResult2 = " + str(powText2))
#     decryptedText = ''.join(chr(i) for i in powText2)

#     return decryptedText

# def isPrime(p):
#     for i in range(2,math.floor(math.sqrt(p))):
#         if p % i == 0:
#             return False
    
#     return p > i

# class Main:
#     # test1
#     p1,q1 = 11,19

#     p2,q2 = 529, 419

#     # print(isPrime(p2))
#     # print(isPrime(q2))

    
#     sentence2 = "My name is ro50s."
#     print(f"experiment with {sentence2}\n")
#     d2 = rsa(p1,q1,sentence2)
#     large2 = rsa(p2,q2,sentence2)
#     print("d2 == large2:" + d2 == large2)
#     print("original: " + sentence2 + ", ET = " + d2)


#     s3 = "f"
#     print(f"experiment with {s3}\n")
#     decrypt3 = rsa(p1,q1,s3)
#     print("original = " + s3 + ", E2 = " + decrypt3)

#     m5 = "141"
#     print(f"experiment: {m5}\n")
#     d5 = rsa(p1,q1,m5)
#     print("original = " + m5 + ", E = " + d5)

#     m6 = "a"
#     print(f"experiment: {m6}")
#     d6 = rsa(p1,q1,m6)
#     print("original = " + m6 + ", E = " + d6)

#     m7 = "私の名前はro50sです。"
#     d7 = rsa(p1,q1,m7)
#     print("original = " + m7 + ", E = " + d7)

#     m8 = "私"
#     d8 = rsa(p1,q1,m8)
#     print("original = " + m8 + ", E = " + d8)