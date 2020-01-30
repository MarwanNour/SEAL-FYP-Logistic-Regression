#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main()
{
	cout << "\n--------- Microsoft SEAL DEMO using the BFV scheme ---------\n" << endl ;
	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

	parms.set_plain_modulus(1024);

	auto context = SEALContext::Create(parms);

	cout << endl;
	cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	/*
    As an example, we evaluate the degree 4 polynomial

        4x^4 + 8x^3 + 8x^2 + 8x + 4

    over an encrypted x = 6. The coefficients of the polynomial can be considered
    as plaintext inputs, as we will see below. The computation is done modulo the
    plain_modulus 1024.

    To get started, we create a plaintext containing the constant 6. For the
    plaintext element we use a constructor that takes the desired polynomial as
    a string with coefficients represented as hexadecimal numbers.
    */
	int x = 6;
	Plaintext x_plain(to_string(x));
	cout << "Express x = " + to_string(x) +
				" as a plaintext polynomial 0x" + x_plain.to_string() + "."
		 << endl;

	/* We then encrypt the plaintext, producing a ciphertext. */
	Ciphertext x_encrypted;
	cout << "Encrypt x_plain to x_encrypted." << endl;
	encryptor.encrypt(x_plain, x_encrypted);

	/* In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
    whose coefficients are integers modulo the product of the primes in the
    coeff_modulus. The number of polynomials in a ciphertext is called its `size'
    and is given by Ciphertext::size(). A freshly encrypted ciphertext always
    has size 2. */
	cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

	/* There is plenty of noise budget left in this freshly encrypted ciphertext. */
	cout << "    + noise budget in freshly encrypted x: "
		 << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

	/* We decrypt the ciphertext and print the resulting plaintext in order to
    demonstrate correctness of the encryption. */
	Plaintext x_decrypted;
	cout << "    + decryption of x_encrypted: ";
	decryptor.decrypt(x_encrypted, x_decrypted);
	cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

	/* When using Microsoft SEAL, it is typically advantageous to compute in a way
    that minimizes the longest chain of sequential multiplications. In other
    words, encrypted computations are best evaluated in a way that minimizes
    the multiplicative depth of the computation, because the total noise budget
    consumption is proportional to the multiplicative depth. For example, for
    our example computation it is advantageous to factorize the polynomial as

        4x^4 + 8x^3 + 8x^2 + 8x + 4 = 4(x + 1)^2 * (x^2 + 1)

    to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
    (x^2 + 1) separately, before multiplying them, and multiplying by 4.

    First, we compute x^2 and add a plaintext "1". We can clearly see from the
    print-out that multiplication has consumed a lot of noise budget. The user
    can vary the plain_modulus parameter to see its effect on the rate of noise
    budget consumption. */

	cout << "Compute x_sq_plus_one (x^2+1)." << endl;
	Ciphertext x_sq_plus_one;
	evaluator.square(x_encrypted, x_sq_plus_one);
	Plaintext plain_one("1");
	evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

	/*
    Encrypted multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform a squaring, and observe both size growth and noise budget
    consumption.
    */
	cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
	cout << "    + noise budget in x_sq_plus_one: "
		 << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

	/*
    Even though the size has grown, decryption works as usual as long as noise
    budget has not reached 0.
    */
	Plaintext decrypted_result;
	cout << "    + decryption of x_sq_plus_one: ";
	decryptor.decrypt(x_sq_plus_one, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	/*
    Next, we compute (x + 1)^2.
    */
	cout << "Compute x_plus_one_sq ((x+1)^2)." << endl;
	Ciphertext x_plus_one_sq;
	evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
	evaluator.square_inplace(x_plus_one_sq);
	cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
	cout << "    + noise budget in x_plus_one_sq: "
		 << decryptor.invariant_noise_budget(x_plus_one_sq)
		 << " bits" << endl;
	cout << "    + decryption of x_plus_one_sq: ";
	decryptor.decrypt(x_plus_one_sq, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	/*
    Finally, we multiply (x^2 + 1) * (x + 1)^2 * 4.
    */
	cout << "Compute encrypted_result (4(x^2+1)(x+1)^2)." << endl;
	Ciphertext encrypted_result;
	Plaintext plain_four("4");
	evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
	evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
	cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
	cout << "    + noise budget in encrypted_result: "
		 << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
	cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;

	cout << endl;
	cout << "~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

	/* Applying the same example but with relinearization */
	cout << "Generate relinearization keys." << endl;
	auto relin_keys = keygen.relin_keys();

	/* We now repeat the computation relinearizing after each multiplication. */
	cout << "Compute and relinearize x_squared (x^2), then compute x_sq_plus_one (x^2+1)" << endl;
	Ciphertext x_squared;
	evaluator.square(x_encrypted, x_squared);
	cout << "    + size of x_squared: " << x_squared.size() << endl;
	evaluator.relinearize_inplace(x_squared, relin_keys);
	cout << "    + size of x_squared (after relinearization): "
		 << x_squared.size() << endl;
	evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
	cout << "    + noise budget in x_sq_plus_one: "
		 << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;
	cout << "    + decryption of x_sq_plus_one: ";
	decryptor.decrypt(x_sq_plus_one, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	Ciphertext x_plus_one;
	cout << "Compute x_plus_one (x+1), then compute and relinearize x_plus_one_sq ((x+1)^2)." << endl;
	evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
	evaluator.square(x_plus_one, x_plus_one_sq);
	cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
	evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
	cout << "    + noise budget in x_plus_one_sq: "
		 << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
	cout << "    + decryption of x_plus_one_sq: ";
	decryptor.decrypt(x_plus_one_sq, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

	cout << "Compute and relinearize encrypted_result (4(x^2+1)(x+1)^2)." << endl;
	evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
	evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
	cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
	evaluator.relinearize_inplace(encrypted_result, relin_keys);
	cout << "    + size of encrypted_result (after relinearization): "
		 << encrypted_result.size() << endl;
	cout << "    + noise budget in encrypted_result: "
		 << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

	cout << endl;
	cout << "NOTE: Notice the increase in remaining noise budget." << endl;

	/* Relinearization clearly improved our noise consumption. We have still plenty
    of noise budget left, so we can expect the correct answer when decrypting. */
	cout << "Decrypt encrypted_result (4(x^2+1)(x+1)^2)." << endl;
	decryptor.decrypt(encrypted_result, decrypted_result);
	cout << "    + decryption of 4(x^2+1)(x+1)^2 = 0x"
		 << decrypted_result.to_string() << " ...... Correct." << endl;
	cout << endl;

	/*  For x=6, 4(x^2+1)(x+1)^2 = 7252. Since the plaintext modulus is set to 1024,
    this result is computed in integers modulo 1024. Therefore the expected output
    should be 7252 % 1024 == 84, or 0x54 in hexadecimal. */
}
