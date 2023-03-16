# RSA - Public Key Cryptography

**Public key cryptography** is a technique for secure communication using a pair of keys: one **public** and one **private**.

## Files In The Repository

1. Makefile
2. README.md
3. rsa.h
4. rsa.c
5. randstate.h
6. randstate.c
7. numtheory.h
8. numtheory.c
9. keygen.c
10. encrypt.c
11. decrypt.c

# Make commands

```
$ make clean
```

This command will make the repository clean by deleting the object file and executable generated.


```
$ make format
```

This command will format C file into clang format.

```
$ make
```

This command will just compile other C files and make the executable and object file for **keygen.c**,**encrypt.c** and **decrypt.c**.

## Running the program

```
$ make
```

This command will just compile and make the executable and object file for **keygen.c**,**encrypt.c** and **decrypt.c**..

```
$ ./keygen -flag
```

flags = b,i,n,d,s,v and h you can pass one or many flags together.

### Flags

-b {bits}
:  Minimum bits needed for public key n (default: 256).

-i {iteration}
: Miller-Rabin iterations for testing primes (default: 50).

-n {pbfile}
:  Public key file (default: rsa.pub).

-d {pvfile}
:  Public key file (default: rsa.priv).

-s {seed}
:Random seed for testing.

-v {verbose}
: Display verbose program output.

-h {help}
:Display program help and usage.

```
$./encrypt -flags
```

flags = i,o,n,v and h.

### Flags

-i {infile}
: Input file of data to encrypt (default: stdin).

-o {outfile}
: Output file for encrypted data (default: stdout).

-n {pbfile}
: Public key file (default: rsa.pub).

-v {verbose}
: Display verbose program output.

-h {help}
: Display program help and usage.



```
$./decrypt -flag
```

### Flags

-i {infile}
: Input file of data to encrypt (default: stdin).

-o {outfile}
: Output file for encrypted data (default: stdout).

-n {pbfile}
: Public key file (default: rsa.priv).

-v {verbose}
: Display verbose program output.

-h {help}
: Display program help and usage.


# Note

If you are a student and if are taking a look at my repository for your assignment, any piece of code that your copy from this repository is completely your responsibility. I should not be held repsonsible for any academic misconduct. 