from asn1 import Encoder, Numbers
from gostcrypto import gosthash
import random


def double_point(P, a, p):
    if P is None:
        return None

    l = ((3 * P[0]**2 + a) * pow(2 * P[1], -1, p)) % p
    x = (l**2 - 2 * P[0]) % p
    y = ((l * (P[0] - x) - P[1]) % p)

    return (x,y)


def add_points(P, Q, a, p):

    if P is None:
        return Q
    if Q is None:
        return P

    if P == Q:
        return double_point(P, a, p)

    l = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)) % p
    x = (l ** 2 - P[0] - Q[0]) % p
    y = ((l * (P[0] - x) - P[1]) % p)

    return (x, y)


def binary_multiplication(P, k, a, p):
    if k == 0:
        return None

    k_binary = bin(k)[2:]
    Q = None

    for i in range(len(k_binary) - 1, -1, -1):
        Q = double_point(Q, a, p)
        if k_binary[len(k_binary) - 1-i] == '1':
            # Если i-й бит равен 1, складываем с P
            Q = add_points(Q, P, a, p)

    return Q


def find_Q(P, q, a, p):
    d = random.randint(1, q - 1)
    return binary_multiplication(P, d, a, p), d


def hash_streebog256(M):
    hash_obj = gosthash.new('streebog256', data=M)
    hash_result = hash_obj.hexdigest()
    return hash_result


def find_e(h, q):
    tmp = int(h, 16)
    a = int(bin(tmp)[2:])
    e = a % q
    if e == 0:
        return 1
    else:
        return e

def find_r_s(P, q, a, p, d, e):
    while 1:
        k = random.randint(1, q - 1)
        C = binary_multiplication(P, k, a, p)
        r = C[0] % q
        if r == 0:
            continue
        s = (r * d + k * e) % q
        if s == 0:
            continue
        return r, s


def SignatureVerification(P, Q, r, s, q, M, a, p):
    r, s = int(r, 2), int(s, 2)
    if r <= 0 or r >= q or s <= 0 or s >= q:
        print('Signature not accepted')
        return
    h = hash_streebog256(M)
    e = find_e(h, q)
    v = pow(e, -1, q)
    z1 = (s * v) % q
    z2 = -(r * v) % q
    C = add_points(binary_multiplication(P, z1, a, p), binary_multiplication(Q, z2, a, p), a, p)
    R = C[0] % q
    if R == r:
        print('Signature accepted')
    else:
        print('Signature not accepted')


def save_asn1(P, Q, a, b, p, q, r, s):
    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Set)
    asn1.enter(Numbers.Sequence)
    asn1.write(b'\x80\x06\x07\x00', Numbers.OctetString)
    asn1.write('gostSignKey', Numbers.UTF8String)
    asn1.enter(Numbers.Sequence)
    asn1.write(int(Q[0]), Numbers.Integer)
    asn1.write(int(Q[1]), Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Sequence)
    asn1.write(int(p), Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(int(a+p), Numbers.Integer)
    asn1.write(int(b), Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(int(P[0]), Numbers.Integer)
    asn1.write(int(P[1]), Numbers.Integer)
    asn1.leave()
    asn1.write(int(q), Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(int(r), Numbers.Integer)
    asn1.write(int(s), Numbers.Integer)
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.leave()
    asn1.leave()

    with open("sign.asn1", "wb") as file:
        file.write(asn1.output())

if __name__ == '__main__':
    p = 57896044625259982827082014024491516445703215213774687456785671200359045162371
    q = 28948022312629991413541007012245758222850495633896873081323396140811733708403
    a = -1
    b = 53956679838042162451108292176931772631109916272820066466458395232513766926866
    xP = 12933162268009944794066590054824622037560826430730236852169234350278155715869
    yP = 18786030474197088418858017573086015439132081546303111294023901101650919011383
    P = [xP, yP]

    with open('file.txt', 'rb') as f:
        M = f.read()


    Q, d = find_Q(P, q, a, p)

    h = hash_streebog256(M)
    e = find_e(h, q)
    r, s = find_r_s(P, q, a, p, d, e)
    r, s = bin(r)[2:], bin(s)[2:]

    print('P = ', P)
    print('Q = ', Q)
    print('p = ', p)
    print('q = ', q)
    print('a = ', a)
    print('b = ', b)
    print('e = ', e)
    print('d = ', d)
    print('r = ', r)
    print('s = ', s)
    print('hash = ', h)

    SignatureVerification(P, Q, r, s, q, M, a, p)

    save_asn1(P, Q, a, b, p, q, r, s)




