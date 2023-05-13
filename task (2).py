from sage.all import *
from secret import flag
import os


def red(m):
    return '\033[1;31m{}\033[1;m'.format(m)


def green(m):
    return '\033[1;32m{}\033[1;m'.format(m)

def text_to_poly(text: bytes, zfill_size: int):
    text_integer = int.from_bytes(text, 'big')
    text_binary = bin(text_integer)[2:].zfill(zfill_size)
    text_binary_list = list(map(int, list(text_binary)))

    return R_l(text_binary_list)


def poly_to_text(poly, binary_list_size: int) -> bytes:
    text_binary_list = list(map(str, poly.list()))[:binary_list_size]
    text_binary = '0b' + ''.join(text_binary_list)
    text_integer = int(text_binary, 2)

    return text_integer.to_bytes(binary_list_size // 8 + 1, 'big')


def pad(text: bytes) -> bytes:
    pad_size = block_size_in_bytes - len(text) % block_size_in_bytes
    pad_byte = pad_size.to_bytes(1, 'big')

    return text + pad_size * pad_byte


def B_random_element(ring, coef_ring, degree: int):
    return ring(coef_ring.random_element(degree=degree))


def keygen():
    f = 1
    F_s = 1
    F_l = 1

    for i in range(1, N_f + 1):
        flag = False

        while not flag:
            f_i = B_random_element(R_l, F_x, d_f)
            try:
                F_i_s = ~R_s(f_i)
                F_i_l = ~R_l(f_i)

                flag = True

                f *= f_i  # private key
                F_s *= F_i_s
                F_l *= F_i_l
            except:
                pass

    g = B_random_element(R_l, F_x, d_g)
    h = g * F_l * R_l(s_modulus)  # public key

    return h, f, F_s


def encrypt(plaintext, h):
    m = text_to_poly(plaintext, block_size)

    phi_0 = R_l(0)

    while phi_0 == R_l(0):
        phi_0 = B_random_element(R_l, F_x, d_phi)

    phi_sum = R_l(0)

    for i in range(1, N_phi + 1):
        phi_i = R_l(F_x.random_element(degree=d_phi))
        phi_sum += R_l(phi_i)

    e = phi_0 * h + R_l(s_modulus) * phi_sum + m

    return poly_to_text(e, l)


def decrypt(ciphertext, f, F_s):
    e = text_to_poly(ciphertext, l)

    a = R_l(f) * e
    m = F_s * R_s(a)

    return poly_to_text(m, block_size)[-block_size_in_bytes:]


"""
    Constants
"""

block_size = 128
block_size_in_bytes = block_size // 8

s = 197
l = 1019
d_phi = 147
d_g = 500
d_f = s - 1
N_f = 3
N_phi = 4

if __name__ == '__main__':
    # preparation
    F_x = PolynomialRing(GF(2), 'x')
    x = F_x.gen()
    s_modulus = x ** s + 1
    l_modulus = x ** l + 1

    R_s = QuotientRing(F_x, F_x.ideal(s_modulus))
    R_l = QuotientRing(F_x, F_x.ideal(l_modulus))

    # tests
    for key_test in range(10):
        public_key, private_key_1, private_key_2 = keygen()

        print("Public Key:", poly_to_text(public_key, l))
        print("Private Key #1:", poly_to_text(private_key_1, l))
        print("Private Key #2:", poly_to_text(private_key_2, l))

        for test in range(10):
            message = pad(os.urandom(test))
            message_blocks = [message[i: i + block_size_in_bytes] for i in range(0, len(message), block_size_in_bytes)]
            encrypted_blocks = []
            decrypted_blocks = []

            for block in message_blocks:
                encrypted_block = encrypt(block, public_key)
                encrypted_blocks.append(encrypted_block)

            for block in encrypted_blocks:
                decrypted_block = decrypt(block, private_key_1, private_key_2)
                decrypted_blocks.append(decrypted_block)

            decrypted_message = b''.join(decrypted_blocks)

            try:
                assert message == decrypted_message
                print("Test #{0}.{1}: {2}".format(key_test, test, green("success")))
            except:
                print("Test #{0}.{1}: {2}".format(key_test, test, red("failure")))
                print("DEBUG INFO:")
                print("-> message:", message)
                print("-> decrypted message:", decrypted_message)

    # main
    print("\nLet's start...")
    public_key, private_key_1, private_key_2 = keygen()
    print("Public Key:", poly_to_text(public_key, l))

    message = pad(flag)
    message_blocks = [message[i: i + block_size_in_bytes] for i in range(0, len(message), block_size_in_bytes)]

    print("Blocks:")
    for block in message_blocks:
        encrypted_block = encrypt(block, public_key)
        print(encrypted_block)
        print("Just for check:", decrypt(encrypted_block, private_key_1, private_key_2))
