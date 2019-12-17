# Math functions used in RSA Encryption utilizing a block cipher.

# TODO: Minimum working code for block implementation.  Needs to be refactored for clarity.
# TODO: Make newly created functions single-purpose (break out functionality into individual functions).
# TODO: Add comments.

import random


# =====================================================================================================================|
# ===============================================PREP THE MESSAGE FUNCTIONS============================================|
# =====================================================================================================================|

def block_convert_text(_string):
    """
    Converts a string of letters to a numerical format.  Groups letters
    into blocks to avoid frequency analysis exploit.

    Args:
        _string (string): message to be encoded using block conversion.

    Returns:
        list: message blocked into chunks and converted to numbers.
    """

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _string = _string.upper()
    conversion_table = {char: idx for idx, char in enumerate(alphabet)}
    return [conversion_table[char] for char in _string]


def block_convert_num(_list):
    """
    Converts a list of block encoded characters to a string.

    Args:
         _list (list): List of block encoded letters in the form of ints.

    Returns:
        string: message obtained from converting block cipher text.

    """

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    conversion_table = {idx: char for idx, char in enumerate(alphabet)}
    return "".join([conversion_table[num] for num in _list if num in conversion_table])


def find_block_size(n):
    """
    Finds the optimal block size for block encryption using public key token n.

    Example: if our n is 2748, 2525 < 2748 < 252525, so our
    block size would be len(str(2525)) = 4.
    If our n is 2327, 25 < 2327 < 2525, so our block size
    would be len(str(25)) = 2.

    Args:
         n (int): Public encryption token n.

    Returns:
        int: Optimal block ("chunking") size for prepping the message.

    """
    adder = "25"
    multiplier = len(str(n)) // 2
    guess = adder * multiplier
    if int(guess) < n:
        return len(guess)
    else:
        return len(guess) - 2


def separate_string_to_blocks(_string, length):
    """
    Helper function for preparing our plaintext message for encryption.
    Chunks a string into length-sized blocks and pushes them to a list.

    Args:
         _string (string): String to be broken into length-sized blocks.
         length (int): Size of individual blocks desired.

    Returns:
        list: Length sized chunks of the string pushed into a list.

    """
    return [_string[0 + i:length + i] for i in range(0, len(_string), length)]


def prep_message(_string, n):
    """
    Takes a plain-text message and converts it into a list of numbers that
    will be sent individually through an RSA encryption algorithm
    (the "block" step in "block encryption").

    Args:
         _string (string): Plaintext message to be blocked.
         n (int): Public key token n.  See below for usage.

    Returns:
        list: Blocked plaintext message to be passed on to encryption algorithm.

    """
    _string = _string.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    conversion_table = {char: str(idx) for idx, char in enumerate(alphabet)}
    for char in conversion_table:
        if len(conversion_table[char]) < 2:
            conversion_table[char] = "0" + conversion_table[char]
    encoded_message = ""
    for char in _string:
        encoded_message = encoded_message + conversion_table[char]
    block_size = find_block_size(n)
    message = separate_string_to_blocks(encoded_message, block_size)
    while len(message[-1]) < len(message[-2]):
        message[-1] = message[-1] + "00"
    return message


# =====================================================================================================================|
# ===============================================ESSENTIAL MATH FUNCTIONS==============================================|
# =====================================================================================================================|

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
    prepped_message = prep_message(message, n)
    print(prepped_message)
    return [fme(int(block), e, n) for block in prepped_message]


def convert_prepped_to_plaintext(_list):
    """
    Breaks a plaintext blocked message up into the format needed for block_convert_num.

    Arguments:
        _list (list): Blocked message.

    Returns:
        list: List of individual integers to be processed back to alphabetic characters.
    """
    message_concat = "".join(_list)
    return [int(char) for char in separate_string_to_blocks(message_concat, 2)]


def decode(n, d, cipher_text):
    """
    Decrypts a message using a private key.

    Arguments:
        n (int): Public key token n.
        d (int): Private key token d.
        cipher_text (list): List of block cipher blocks (ints)
    Returns:
        string: Decrypted message.
    """
    block_size = find_block_size(n)
    unformatted_decrypted_message = [str(fme(char, d, n)) for char in cipher_text]
    formatted_decrypted_message = []
    for word in unformatted_decrypted_message:
        leading_zeros_to_add = block_size - len(word)
        word = ("0" * leading_zeros_to_add) + word
        formatted_decrypted_message.append(word)
    return block_convert_num(convert_prepped_to_plaintext(formatted_decrypted_message))
