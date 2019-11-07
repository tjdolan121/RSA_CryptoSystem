from RSA import *
import time


def main():
    choice = input("Tutorial: type t\nGet Keys: type k\nencode: type e\ndecode: type d\n")
    if choice == "t":
        print(
            "Some Primes: 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103")
        p = int(input("Welcome to the RSA Tutorial! Pick a prime: "))
        q = int(input("Pick another prime: "))
        n, e, d = find_key_pair(p, q)  # Get Key Pair
        print(f"Your primes were used to calculate this random key:\n\tpublic key: e={e}, n={n}\n\tprivate key: d={d}")
        m = input("Let's encrypt a message! Type it here: ")
        c = encode(n, e, m)  # encode
        print(f"Here's your encrypted message!:\n\t{c}")
        print("Let's decrypt it now using your private key!")
        print("Decrypting...")
        time.sleep(2)
        decrypted_m = decode(n, d, c)  # decode
        if decrypted_m == m:
            print(f"Decrypted message: \n\t{decrypted_m}")
            print("It worked! Thanks for using the RSA tutorial!")
        else:
            print("Whoops, something went wrong!")

    elif choice == "k":
        p = int(input("Enter a prime number: "))
        q = int(input("Enter another prime number: "))
        n, e, d = find_key_pair(p, q)  # Get Key Pair
        print(f"Public Key (e, n) = ({e, n})\nPrivate Key d = {d}")
    elif choice == "e":
        e = int(input("Enter public key e: "))
        n = int(input("Enter public key n: "))
        m = input("Enter your message: ")
        print(f"Here is your encoded message:\n\t{encode(n, e, m)}")  # encode
    elif choice == "d":
        c = input("Paste your cipher text message here: ")
        c = list(map(int, c[1:-1].split(", ")))  # Format message: should inputed as a list
        d = int(input("Enter decryption token d: "))
        n = int(input("Enter Public key n: "))
        print(f"Here is your decoded message:\n\t {decode(n, d, c)}")  # decode
    else:
        print("Invalid choice")


if __name__ == '__main__':
    main()
