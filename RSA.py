# Math functions used in RSA Encryption.


import random


def convert_text(_string):
    """
    Converts a string to ASCII code for use in RSA.

    Args:
         _string (string): message to be encoded.

    Returns:
        list: message separated by character and converted to ASCII code.

    """

    return [ord(char) for char in list(_string)]


def convert_num(_list):
    """
    Converts a list of ASCII encoded characters to a string.

    Args:
         _list (list): ASCII list to be decoded to string.

    Returns:
        string: message obtained from converting ASCII code.

    """

    return "".join(map(chr, _list))


def convert_binary_string(_int):
    """
    Converts a base 10 integer to binary.
    Source: Pseudocode from Discrete Mathematics and Its Applications, Rosen.

    Args:
         _int (int): Base 10 integer to be converted to binary.

    Returns:
        string: Converted binary value.

    Raises:
        ValueError: if input is not a valid integer.

    """
    if _int < 0:
        raise ValueError(f"Invalid integer given for convert_binary_string")

    if _int == 0:  # edge case for below algorithm
        return "0"
    bits = []
    while _int > 0:
        _int, r = divmod(_int, 2)  # retrieve quotient and modulus
        bits.insert(0, str(r))  # push modulus to accumulator
    return "".join(bits)


def fme(b, n, m):
    """
    Finds the modulus of a large number using fast modular exponentiation.
    Source: Pseudocode from Discrete Mathematics and Its Applications, Rosen.
    Args:
         b (int): Base 10 integer.
         n (int): Power to raise b to.
         m (int): Quotient for modulo operation.

    Returns:
        int: resulting modulus from b^n mod m.

    """
    n = convert_binary_string(n)  # convert n to binary
    x = 1
    power = b % m  # initial power
    for i in range(len(n)):  # iterate over the range of the number of binary digits
        if int(n[-(i + 1)]) == 1:  # want to go in reverse order and convert elements to int
            x = (x * power) % m  # if the digit is 1, increment x
        power = (power * power) % m  # adjust to next power
    return x


def euclidian_algorithm(a, b):
    """
    Calculates the greatest common divisor between two integers using the Euclidean Algorithm.
    Source: Pseudocode from Discrete Mathematics and Its Applications, Rosen.
    Args:
         a (int): First integer.
         b (int): Second integer.

    Returns:
        int: Greatest common divisor of a and b.

    """
    while b != 0:
        r = a % b  # take modulus of a and b
        a = b  # set a to old quotient
        b = r  # set b to the modulus
    return a


def extended_euclid(b, m):
    """
    Algorithm for finding inverse of b mod m.
    Source: Pseudocode from Discrete Mathematics and Its Applications, Rosen.
    Args:
         b (int): Dividend in modulo operation.
         m (int): Divisor in modulo operation.

    Returns:
        int: Inverse of b modulo m.
    """
    original_b = b  # store the initial values for b and m
    original_m = m
    s1, t1 = (1, 0)  # initialize s1, t1, s2, t2, part of loop invariant
    s2, t2 = (0, 1)
    while m > 0:
        # perform an iteration of euclid's algorithm:
        k = b % m
        q = b // m
        b = m
        m = k
        # then update our coeffiecients:
        s1_, t1_ = (s2, t2)
        s2_, t2_ = (s1 - q * s2, t1 - q * t2)
        s1, t1 = (s1_, t1_)
        s2, t2 = (s2_, t2_)
    # we want a positive modular inverse, so add divisor if necessary:
    if s1 < 0:
        s1 += original_m
    return s1


def find_public_key(p, q):
    """
    Generates a public key pair for RSA encryption.

    Arguments:
        p (int): A prime number.
        q (int): A different prime number.

    Returns:
        (int, int): Public key token n, public key token e.
    """
    n = p * q  # calculate n
    pq_less = (p - 1) * (q - 1)  # calculate phi
    e_found = False  # loop conditional
    while not e_found:
        e = random.randrange(2, p - 1)  # generate a random e
        cond_1 = e != p  # check 1: e doesn't equal p (should never happen)
        cond_2 = e != q  # check 2: e doesn't equal q
        cond_3 = euclidian_algorithm(e, pq_less) == 1  # gcd(e, phi) == 1
        if all((cond_1, cond_2, cond_3)):  # if all conditions are met, exit the loop
            e_found = True
    return n, e


def find_private_key(p, q, e):
    """
    Generates a Private Key for RSA encryption.

    Arguments:
        p (int): A prime number.
        q (int): A different prime number.
        e (int): A public token e associated with p & q.

    Returns:
        int: Private decryption token d.
    """
    pq_less = (p - 1) * (q - 1)  # calculate phi
    d = extended_euclid(e, pq_less)  # find modular inverse using EEA
    return d  # return inverse


def find_key_pair(p, q):
    """
    Generates a Private/Public Key Pair for RSA encryption.

    Arguments:
        p (int): A prime number.
        q (int): A different prime number.

    Returns:
        (int, int, int): Public key token n, public key token e, private key token d.
"""
    n, e = find_public_key(p, q)  # generate a public key
    d = find_private_key(p, q, e)  # generate a private key
    return n, e, d  # return the key pair


def encode(n, e, message):
    """
    Encrypts a message using a public key.

    Arguments:
        n (int): Public key token n.
        e (int): Public key token e.
        message (string): Plain-text message for encryption.

    Returns:
        list: Encrypted message.
    """

    return [fme(char, e, n) for char in convert_text(message)]  # Use fme and convert_text to encode


def decode(n, d, cipher_text):
    """
    Decrypts a message using a private key.

    Arguments:
        n (int): Public key token n.
        d (int): Private key token d.

    Returns:
        string: Decrypted message.
    """
    return convert_num([fme(char, d, n) for char in cipher_text])  # Use fme and convert_num to decode
