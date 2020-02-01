#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

void integerEncoding()
{
    cout << "--------- Integer Encoding ---------\n"
         << endl;

    // Set the parameters
    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(512);
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    // Create IntegerEncoder
    IntegerEncoder encoder(context);

    // Encode two values
    int val1 = 10;
    Plaintext plain1 = encoder.encode(val1);
    cout << "Encode " << val1 << " as polynomial " << plain1.to_string() << endl;

    int val2 = 12;
    Plaintext plain2 = encoder.encode(val2);
    cout << "Encode " << val2 << " as polynomial " << plain2.to_string() << endl;

    // Encrypt the encoded values
    Ciphertext cipher1, cipher2;
    cout << "\nEncrypt plain1 to cipher1 and plain2 to cipher2" << endl;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);
    cout << "   + NOISE budget in cipher1: " << decryptor.invariant_noise_budget(cipher1) << " bits" << endl;
    cout << "   + NOISE budget in cipher2: " << decryptor.invariant_noise_budget(cipher2) << " bits" << endl;

    // Example: Compute (cipher1*cipher2) - cipher1
    Ciphertext cipherResult;
    cout << "\nComputing (cipher1*cipher2) - cipher1:" << endl;
    Ciphertext cipher1_mul_cipher2;
    evaluator.multiply(cipher1, cipher2, cipher1_mul_cipher2);
    evaluator.sub(cipher1_mul_cipher2, cipher1, cipherResult);
    cout << "   + NOISE budget in cipherResult: " << decryptor.invariant_noise_budget(cipherResult) << " bits" << endl;

    // Decrypt
    Plaintext plain_result;
    decryptor.decrypt(cipherResult, plain_result);
    cout << "Decrypted plaintext result:\n\t" << plain_result.to_string() << endl;

    // Decode
    cout << "Decoded Result:\n\t" << encoder.decode_int32(plain_result) << endl;


}

int main()
{

    integerEncoding();
    return 0;
}