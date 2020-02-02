# SEALDemo
A Microsoft SEAL Demo based on the examples already provided in the library. 

## Setup for Linux
First, make sure you have Microsoft SEAL installed. Follow the tutorial on https://github.com/Microsoft/SEAL.
If you have made any changes to the file name or added other files you will need to modify the `CMakeLists.txt` file accordingly.

To Build the project for the first time you need to run `cmake .` to generate the proper Makefile then you can build it with `make`.

## Setup for Windows
Refer to the Windows installation of SEAL in https://github.com/Microsoft/SEAL.

Place the `.cpp` file(s) in the Source Files, and then build the project.

## About the C++ files
All the explanations are based on the comments and code from the SEAL examples. If you need a more detailed explaination, please refer to the original SEAL examples.

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

### 4 - CKKS
The `CKKS` encryption scheme focuses on performing operations on encrypted real and complex numbers. Homomorphic multiplication in CKKS causes the `scales` in ciphertexts to grow. The scale can be considered as the bit precision of the encoding. The scale must not get too close to the total size of `coeff_modulus`. You can rescale to reduce the scale and stabilize the scale expansion. `Rescaling` is a type of `modulus switching`, it removes the last of the primes from the `coeff_modulus` but it scales down the ciphertext by the removed prime.

Suppose that the scale in a CKKS ciphertext is `S` and the last prime in the `coeff_modulus` is `P`. Rescaling to the next level changes the scale to `S/P` and removes the prime `P` from the `coeff_modulus` (just like in Modulus Switching). A good strategy is to set the initial scale `S` and primes `P_i` to be very close to each other. If ciphertexts have scale `S` before multiplication then they will have scale `S^2` after multiplication and then `S^2/P_i` after rescaling thus `S^2/P_i` will be close to S again. Generally, for a circuit of depth `D`, we need to rescale `D` times, i.e., we need to be able to remove `D` primes from the `coeff_modulus`. Once we have only one prime left in the `coeff_modulus`, the remaining prime must be larger than `S` by a few bits to preserve the pre-decimal-point value of the plaintext.

Therefore a generally good strategy is to choose the parameters for the CKKS scheme as follows:
- Choose a `60 bit` prime as as the first prime in `coeff_modulus` giving us the highest precision when decrypting
- Choose another `60 bit` prime as the last prime in `coeff_modulus`
- Choose the intermediate primes to be close to each other

The values I have used are `{60, 40, 40, 60}` with a `poly_modulus_degree = 8192` which yields a `coeff_modulus` of `200 bits` in total which is below max bit count for the `poly_modulus_degree`: `CoeffModulus::MaxBitCount(8192)` returns `218`. The initial scale is set to `2^40`. At the last level, this leaves us `60-40 = 20 bits` of precision before the decimal point and around `10 to 20 bits` of precision after the decimal point. Since our intermediate primes are `40 bits` which is very close to `2^40` we are able to achieve stabilization as described earlier.

In the example, we're evaluating the polynomial `PI*x^3 + 0.4x + 1`. When computing `x^2` (to compute `x^3` later), you will notice that the scale will grow to `2^80`. After rescaling the new scale should be close to `2^40` (NOT equal).