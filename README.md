# RSA CryptoSystem

![NMC](RSA.png?raw=true "RSA")

#### CONTEXT: This was a project I had for an undergraduate CS class.

#### OVERVIEW:

#### This app implements an RSA encryption protocol.  Two methods are shown:

* An ASCII based method
* A block cipher method

#### The ASCII based method encrypts each letter of a plaintext message individually, making it prone to frequency analysis attacks.
#### The block cipher method is an improvement I implemented after the semester ended.  It "chunks" a message into character strings that are then encrypted.  This method helps prevent frequency analysis attacks.

#### Additionally, this project includes some basic codebreaking algorithms that can be used to attack RSA.  The caveat is that these only work when small primes are chosen in the creation of the public key.  When large primes are used, as with real-world encryption, these codebreaking algorithms are not effective.

#### COMPONENTS:

* RSA.py: The preprocessing and mathematical functions used for the ASCII method.
* RSA_block.py: The preprocessing and mathematical functions used for the block cipher method.
* main.py: The main program that implements the RSA CryptoSystem.
* CodeBreakers.py: A collection of a few codebreaking algorithms.  factor_3() was an original creation based on a common method for finding primes.

### Feel free to message me if you have any questions!
