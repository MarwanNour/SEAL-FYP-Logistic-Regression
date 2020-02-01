# SEALDemo
Microsoft SEAL Demo based on the examples already provided in the library. 

## Setup for Linux
First, make sure you have Microsoft SEAL installed. Follow the tutorial on https://github.com/Microsoft/SEAL.
If you have made any changes to the file name or added other files you will need to modify the `CMakeLists.txt` file accordingly.

To Build the project for the first time you need to run `cmake .` to generate the proper Makefile then you can build it with `make`.

## Setup for Windows
Refer to the Windows installation of SEAL in https://github.com/Microsoft/SEAL.

Place the `.cpp` file(s) in the Source Files, and then build the project.

## About the C++ files
### 1 - BFV
The first file is the `1_bfv.cpp`. It contains an example on how to use the bfv scheme in SEAL. The BFV encryption scheme is used mainly to encrypt integers. It requires three parameters:
- Degree of Polynomial Modulus: `poly_modulus_degree`
- Ciphertext Coefficient Modulus: `coeff_modulus`
- Plaintext Coefficient Modulus: `plain_modulus`

Since BFV is a homomorphic encryption scheme it allows computations on ciphertexts. However there exists a limit to those computations. Each ciphertext has an `invariant noise budget` measured in bits that is consumed on every ciphertext operation. If the noise budget were to reach 0, the ciphertext would be too corrupted for decryption.
The noise budget is computed as follows: `log2(coeff_modulus/plain_modulus)`. Choosing a larger `coeff_modulus` will give you a larger noise budget but will make computations a bit slower. The example provided uses a helper function from SEAL to create this parameter.

The `size` of a ciphertext in SEAL is the number of polynomials. A new ciphertext has a size of `2`. Homomorphic Multiplication increases the size of the ciphertext: If two ciphertexts have sizes `M` and `N` then their multiplication will yield a size of `M+N-1`. The larger the ciphertext size the greater the consuption rate of the noise budget will be.

It is possible to reduce the size of ciphertexts from `3` to `2` by applying `Relinearization` to the ciphertexts. However this procedure comes at a certain computational cost.


### 2 - Encoding
There are 3 types of encoding that can be used in SEAL: `Integer Encoding` , `Batch Encoding` and `CKKS Encoding`.
The reason you may want to encode your Plaintext before encrypting it is to avoid integer overflow. Integer overflow happens when the plaintext coefficients exceed `plain_modulus`.

### 3 - Levels
The `modulus switching chain` is a chain of other encryption parameters derived from the original parameters. The parameters in the modulus switching chain are the same as the original parameters with the exception that size of the coefficient modulus is decreasing going down the chain. The example provided shows a `coeff_modulus` of 5 primes of sizes `{50, 30, 30, 50, 50}` bits. Thus, there are 5 levels in this chain: 
- `{50, 30, 30, 50, 50}` -> Level 4 (Key level)
- `{50, 30, 30, 50}` -> Level 3 (Data level)
- `{50, 30, 30}`-> Level 2
- `{50, 30}` -> Level 1
- `{50}` -> Level 0 (Lowest level)


`Modulus Switching` is a technique of changing the ciphertext parameters down the chain. You may want to use this to gain computational performance from having smaller parameters. This method may reduce your ciphertext noise budget. If there is no need to perform further computations on a ciphertext, you can switch it down to the smallest (last) set of parameters in the chain before decrypting it.