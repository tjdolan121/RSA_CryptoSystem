import math
from RSA import *


def factor(n):
    for integer in range(2, n - 1):  # search all numbers from 2 to n-1
        if n % integer == 0:  # if the number evenly divides n, it's a factor
            return integer, int(n / integer)  # return the factor pair.


def break_code(n, e, c):
    p, q = factor(n)  # find p and q using the factor algorithm
    d = find_private_key(p, q, e)  # steal their private key
    plain_text = [fme(char, d, n) for char in c]  # decode their message.
    return convert_num(plain_text)


# IMPROVEMENT: SKIP EVENS IF INTEGER IS ODD.
def factor_1(n):
    if n % 2 != 0:  # if the number is odd:
        for integer in range(3, n - 1, 2):  # just check odd numbers
            if n % integer == 0:
                return integer, int(n / integer)
    else:
        for integer in range(2, n - 1, 2):  # if the number is even, check even numbers
            if n % integer == 0:
                return integer, int(n / integer)


# IMPROVEMENT: ONLY LOOK AT FACTORS UP TO SQRT(N).
def factor_2(n):
    for integer in range(2, math.ceil(math.sqrt(n))):  # only iterate up to the sqrt of n.
        if n % integer == 0:
            return integer, int(n / integer)


# IMPROVEMENT: RHO FACTORIZATION
# DOESN'T ALWAYS WORK, CAN GET STUCK IN AN ENDLESS LOOP
def rho_factorize(n):
    x = 2
    found = False
    while not found:
        y = ((x ** 2) + random.randint(1, n)) % n  # Pseudo random number generator
        p = euclidian_algorithm(abs(y - x), n)  # based on the birthday problem
        if (p > 1):
            return p, int(n / p)


# ONLY CHECKS PRIMES (USEFUL FOR RSA).
# REFERENCE:  https://www.geeksforgeeks.org/new-algorithm-to-generate-prime-numbers-from-1-to-nth-number/
def factor_3(n):
    for integer in range(2, n - 1):
        if (n % (6 * integer + 1)) == 0:  # generate a prime
            return (6 * integer + 1), int(n / (6 * integer + 1))  # check it
        if (n % (6 * integer - 1)) == 0:  # generate another prime
            return (6 * integer - 1), int(n / (6 * integer - 1))  # check it


# IMPLEMENT THE CODEBREAKING FUNCTION BY USING THE BEST PERFORMING FACTOR ALGORITHM.
def break_code_improved(n, e, c):
    p, q = factor_3(n)  # use factor_3 method
    d = find_private_key(p, q, e)
    plain_text = [fme(char, d, n) for char in c]
    return d, convert_num(plain_text)
