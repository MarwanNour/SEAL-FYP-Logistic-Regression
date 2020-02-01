#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main()
{
    cout << "\n--------- Levels Demo ---------\n"
         << endl;

    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);

    // Use a of coeff_modulus of 5 primes of sizes 50, 30, 30, 50 and bits
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50, 50}));

    // 20 bit poly mod degree
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    auto context = SEALContext::Create(params);

    return 0;
}