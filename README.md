# Overview

kgen is a CLI tool that generates public keys and secret shared keys using the Diffie Hellman key exchange.

## To import this package

```go
import "github.com/joumanae/kgen"
```

## To install the CLI tool

```sh
go install github.com/joumanae/kgen/cmd/kgen@latest
```

## Introduction

Kgen is a project built to acquire the skills to graduate to greenbelt (intermediate Go programmer) at Bitfield consulting. For this project, I decided to write a simple program that demonstrates how the Diffie Hillman Key exchange works. Please note that although the project might help you understand DH, it is not a cryptographic tool.

## Why learn about the Diffie Hillman Key exchange?

I am interested in cryptography, and enjoy learning Go. I am using cryptography projects to improve my skills writing Go. After writing a Caesar Cipher package, and a Vigenere Cipher, the Diffie Hillman key exhange seemed like the next logical adventure.

## Easy math

In this key exchange, two protagonists, let's call them Alice and Bob. Alice and Bob choose a random secret integer, and do not share it with anyone.Alice and Bob both know two other integers, and use these other integers to calculate a public number, a number that they can share with the world.

First, Both Alice and Bob use the same formula to calculate a public number.

Alice: **A = g^a mod p** Bob: **B=g^b mod p**.

Here,'a' represents Alice's private number, 'b', represents Bob's private number, A is Alice's public number, and B is Bob's public number. g represents the base and **mod** the modulus (remember, the two integers known by both Alice & Bob that I mention above).

The strength of the scheme comes from the fact that g^ab mod p = g^ba mod p take a long time to compute by any known algorithm.

Once Alice and Bob compute the shared secret, they can use it as an encryption key, known only to them, for sending messages across the same open communications channel.

Alice sends Bob her public number A, Bob sends to Alice his public number B.

Then both Bob and Alice calculate their secret key: B^a mod p (Alice) A^b mod p (Bob)

**Here's a step by step example of what the exchange would look like using this package:**

Alice: has the base and the modulus and has a secret key generated for her, let's name it s1 Alice types:

```sh
kgen -modulus=13 -base=2 
```

Alice gets:

"This is your public key: 9, & this is your secret key 2.", pn1, secretKey
Bob types:

```sh
kgen -modulus=13 -base=2
```

Bob gets:

```go
"This is your public key: 12, & this is your secret key 3.", pn2, secretKey
```

Alice types:

```sh
kgen -modulus=13 -publicKey=12 -secret=2
```

Alice gets:

This is your shared key: 1.

Bob types:

```sh

kgen -modulus=13 -publickey=9 -secret=3

```

Bob gets:

```sh

This is your shared key: 1.
```

## More about big.Int

It is always interesting to have to use a package I never used before when writing code. If you take a look at my code you will notice that I am using the math/big package. If you already know about it, you can skip the following paragraph.

When generating a public key, you will need more than 64 bytes. Indeed, it is safer (yes, it is going overboard, but why not, sometimes). The package big allows you to implement arbitrary-precision arithmetic a.k.a big numbers of types Int, Rat, or Float. In this case, I am only interested in using the Int type.


## Greenbelt checklist

When you submit your project for grading, it should have:

+ [x] A short, meaningful module name
+ [x] A simple, logical package structure
+ [x] A README explaining briefly what the package/CLI does, how to import/install it, and a couple of examples of how to use it
+ [x] An open source licence (for example MIT)
+ [x] Passing tests with at least 90% coverage, including the CLI
+ [x] Documentation comments for all your exported identifiers
+ [x] Executable examples if appropriate
+ [x] A listing on pkg.go.dev
+ [x] No commented-out code
+ [x] No unchecked errors
+ [x] No 'staticcheck' warnings
+ [x] A Go-compatible release tag (for example v0.1.0)
