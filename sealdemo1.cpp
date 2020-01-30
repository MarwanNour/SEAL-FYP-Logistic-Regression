#include "seal/seal.h"
#include <iostream>
#include <string.h>

using namespace std;
using namespace seal;

void print_parameters(std::shared_ptr<seal::SEALContext> context)
{
	// Verify parameters
	if (!context)
	{
		throw std::invalid_argument("context is not set");
	}
	auto &context_data = *context->key_context_data();

	/*
    Which scheme are we using?
    */
	std::string scheme_name;
	switch (context_data.parms().scheme())
	{
	case seal::scheme_type::BFV:
		scheme_name = "BFV";
		break;
	case seal::scheme_type::CKKS:
		scheme_name = "CKKS";
		break;
	default:
		throw std::invalid_argument("unsupported scheme");
	}
	std::cout << "/" << std::endl;
	std::cout << "| Encryption parameters :" << std::endl;
	std::cout << "|   scheme: " << scheme_name << std::endl;
	std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

	/*
    Print the size of the true (product) coefficient modulus.
    */
	std::cout << "|   coeff_modulus size: ";
	std::cout << context_data.total_coeff_modulus_bit_count() << " (";
	auto coeff_modulus = context_data.parms().coeff_modulus();
	std::size_t coeff_mod_count = coeff_modulus.size();
	for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
	{
		std::cout << coeff_modulus[i].bit_count() << " + ";
	}
	std::cout << coeff_modulus.back().bit_count();
	std::cout << ") bits" << std::endl;

	/*
    For the BFV scheme print the plain_modulus parameter.
    */
	if (context_data.parms().scheme() == seal::scheme_type::BFV)
	{
		std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
	}

	std::cout << "\\" << std::endl;
}

void bfvdemo()
{

	/* ---------------- BFV DEMO -----------------*/
	cout << "----------------- BFV DEMO -----------------\n"
		 << endl;

	// Set up the parameters

	EncryptionParameters params(scheme_type::BFV);

	size_t poly_modulus_degree = 4096;
	params.set_poly_modulus_degree(poly_modulus_degree);

	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

	params.set_plain_modulus(1024);

	/* Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set. */

	auto context = SEALContext::Create(params);
	print_parameters(context);

	cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~ \n"
		 << endl;

	/* Generate public key pk and secret key sk*/

	KeyGenerator keygen(context);

	PublicKey pk = keygen.public_key();
	SecretKey sk = keygen.secret_key();

	/*	To be able to encrypt we need to construct an instance of Encryptor.
	It requires teh public key. */

	Encryptor encryptor(context, pk);

	/* 	Computations on the ciphertexts are performed with the Evaluator class.
	In a real use-case the Evaluator would not be constructed by the same party
	that holds the secret key.	*/

	Evaluator evaluator(context);

	/*	We will of course want to decrypt our results to verify that everything worked,
	so we need to also construct an instance of Decryptor. Note that the Decryptor
	requires the secret key. */

	Decryptor decryptor(context, sk);

	/*
	
	As an example. we evaluate the degree 4 polynomial:

		4x^4 + 8x^3 + 8x^2 + 8x + 4

	over an encrypted x = 6. The coefficients of the polynomial can be considered
	as plaintext inputs. The computation is done modulo the plain_modulus (1024)

	*/

	int x = 6;
	Plaintext x_plain(to_string(x));

	cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

	/* We then encrypt the plaintext, producing a ciphertext */
	Ciphertext x_encrypted;
	cout << "Encrypt x_plain to x_encrypted " << endl;
	encryptor.encrypt(x_plain, x_encrypted);

	/* 	In SEAL, a valid ciphertext consists of 2 or more polynomials whose
	coefficients are integers modulo the product of the primes in the 
	coeff_modulus. The number of polynomials in a ciphertext is called
	its "size" and is given by Ciphertext::size(). A freshly encrypted
	ciphertext always has size = 2 */

	cout << "	+ size of freshly encrypted x: " << x_encrypted.size() << endl;

	/* There is plenty of noise budget left in this freshly encrypted 
	ciphertext */

	cout << "	+ noise budget in freshly encrypted x: "
		 << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

	/* We decrypt the ciphertext and print the resulting plaintext in order
	to demonstrate correctness of the encryption */
	Plaintext x_decrypted;
	cout << "	+ decryption of x_encrypted: ";
	decryptor.decrypt(x_encrypted, x_decrypted);
	cout << "0x" << x_decrypted.to_string() << "..........Correct.\n\n"
		 << endl;

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

	/* Encrypted multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform a squaring, and observe both size growth and noise budget
    consumption. */
	cout << "	+ size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
	cout << "	+ noise budget in x_sq_plus_one: "
		 << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

	/* Even though the size has grown, decryption works as usual as long 
	as noise budget has not reached 0 */

	Plaintext decrypted_result;
	cout << "	+ decryption of x_sq_plus_one: ";
	decryptor.decrypt(x_sq_plus_one, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << "..........Correct.\n"
		 << endl;

	/* Next we compute ( x + 1 )^2 */
	cout << "Compute x_plus_one_sq ((x+1)^2)" << endl;
	Ciphertext x_plus_one_sq;
	evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
	evaluator.square_inplace(x_plus_one_sq);
	cout << "	+ size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
	cout << "	+ noise budget in x_plus_one_sq: "
		 << decryptor.invariant_noise_budget(x_plus_one_sq)
		 << " bits" << endl;

	cout << "	+ decryption of x_plus_one_sq: ";
	decryptor.decrypt(x_plus_one_sq, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << "..........Correct.\n"
		 << endl;

	/* Finally, we multiply (x^2 + 1) * (x+1)^2 * 4 */

	cout << "Compute encrypted_result (4(x^2+1)(x+1)^2)." << endl;
	Ciphertext encrypted_result;
	Plaintext plain_four("4");
	evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
	evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
	cout << "	+ size of encrypted_result: " << encrypted_result.size()
		 << endl;
	cout << "	+ noise budget in encrypted_result: "
		 << decryptor.invariant_noise_budget(encrypted_result)
		 << " bits" << endl;

	cout << "\nNOTE: Decryption can be incorrect if noise budget = 0\n"
		 << endl;

	cout << endl;

	cout << "~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~\n"
		 << endl;

	/* Noise budget has reached 0, which means that decryption cannot be expected
    to give the correct result. This is because both ciphertexts x_sq_plus_one
    and x_plus_one_sq consist of 3 polynomials due to the previous squaring
    operations, and homomorphic operations on large ciphertexts consume much more
    noise budget than computations on small ciphertexts. Computing on smaller
    ciphertexts is also computationally significantly cheaper.
    
	`Relinearization' is an operation that reduces the size of a ciphertext after
    multiplication back to the initial size, 2. Thus, relinearizing one or both
    input ciphertexts before the next multiplication can have a huge positive
    impact on both noise growth and performance, even though relinearization has
    a significant computational cost itself. It is only possible to relinearize
    size 3 ciphertexts down to size 2, so often the user would want to relinearize
    after each multiplication to keep the ciphertext sizes at 2.
    Relinearization requires special `relinearization keys', which can be thought
    of as a kind of public key. Relinearization keys can easily be created with
    the KeyGenerator.
    We use KeyGenerator::relin_keys() to create relinearization keys. */

	cout << "Generate relinearization keys" << endl;
	auto relin_keys = keygen.relin_keys();

	/* We now repeat the computetion relinearizing after each multiplication */

	cout << "Compute and relinearize x_squared (x ^ 2)," << endl;
	cout << "then compute x_sq_plus_on (x^2 + 1)" << endl;

	Ciphertext x_squared;
	// square x
	evaluator.square(x_encrypted, x_squared);

	cout << "	+ size of x_squared: " << x_squared.size() << endl;
	evaluator.relinearize_inplace(x_squared, relin_keys);
	cout << "	+ size of x_squared after relinearlization: "
		 << x_squared.size() << endl;
	// add 1
	evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
	cout << "	+ noise budget in x_sq_plus_one: "
		 << decryptor.invariant_noise_budget(x_sq_plus_one)
		 << " bits" << endl;

	cout << "	+ decryption of x_sq_plus_one: ";
	// decrypt
	decryptor.decrypt(x_sq_plus_one, decrypted_result);
	cout << "0x" << decrypted_result.to_string() << "..........Correct.\n"
		 << endl;

	Ciphertext x_plus_one;
	cout << "Compute x_plus_one (x+1), " << endl;
	cout << "then compute and relinearize x_plus_one_sq ((x+1)^2)" << endl;
	// add 1 to x
	evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
	// square (x+1)
	evaluator.square(x_plus_one, x_plus_one_sq);
	cout << "	+ size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
	cout << "	+ noise budget in x_plus_one_sq: "
		 << decryptor.invariant_noise_budget(x_plus_one_sq)
		 << " bits" << endl;
	cout << "	+ decryption of x_plus_one_sq: ";
	// decrypt
	decryptor.decrypt(x_plus_one_sq, decrypted_result);

	cout << "0x" << decrypted_result.to_string() << "..........Correct.\n"
		 << endl;
}

void integerEncoderDemo()
{
	/* ---------------- Integer Encoder DEMO -----------------*/
	cout << "----------------- Ingteger Encoder DEMO -----------------\n"
		 << endl;

	// Parameters setup
	EncryptionParameters params(scheme_type::BFV);
	size_t poly_modulus_degree = 4096;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	params.set_plain_modulus(512);
	auto context = SEALContext::Create(params);
	print_parameters(context);
	cout << endl;

	// Generate Keys, encryptor, evaluator and decryptor
	KeyGenerator keygen(context);
	PublicKey pk = keygen.public_key();
	SecretKey sk = keygen.secret_key();
	Encryptor encryptor(context, pk);
	Evaluator evaluator(context);
	Decryptor decryptor(context, sk);

	// Generate IntegerEncoder

	IntegerEncoder encoder(context);

	int value1 = 5;
	Plaintext plain1 = encoder.encode(value1);
	cout << "Encode " << value1 << " as polynomial " << plain1.to_string()
		 << " (plain1)," << endl;

	int value2 = -7;
	Plaintext plain2 = encoder.encode(value2);
	cout << string(13, ' ') << "encode " << value2 << " as polynomial " << plain2.to_string()
		 << " (plain2)." << endl;

	// Encrypt the plaintext polynomials

	Ciphertext encrypted1, encrypted2;
	cout << "Encrypt plain1 to encrypted1 and plain2 to encrypted2." << endl;
	encryptor.encrypt(plain1, encrypted1);
	encryptor.encrypt(plain2, encrypted2);
	cout << "    + Noise budget in encrypted1: "
		 << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
	cout << "    + Noise budget in encrypted2: "
		 << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;

	// Example : Compute (-encrypted1 + encrypted2) * encrypted2
	encryptor.encrypt(plain2, encrypted2);
	Ciphertext encrypted_result;
	cout << "Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2." << endl;
	evaluator.negate(encrypted1, encrypted_result);
	evaluator.add_inplace(encrypted_result, encrypted2);
	evaluator.multiply_inplace(encrypted_result, encrypted2);
	cout << "    + Noise budget in encrypted_result: "
		 << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
	Plaintext plain_result;
	cout << "Decrypt encrypted_result to plain_result." << endl;
	decryptor.decrypt(encrypted_result, plain_result);

	/* The coefficients are not even close to exceeding our plain_modulus, 512. */
	cout << "    + Plaintext polynomial: " << plain_result.to_string() << endl;

	/* Decode to obtain an integer result */
	cout << "Decode plain_result." << endl;
	cout << "    + Decoded integer: " << encoder.decode_int32(plain_result);
	cout << "...... Correct." << endl;
}

void batchEncoderDemo()
{
	/* ---------------- Batch Encoder DEMO -----------------*/
	cout << "----------------- Batch Encoder DEMO -----------------\n"
		 << endl;

	/* Batching allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, 
	with each element an integer modulo T */
	EncryptionParameters params(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    /* To enable batching, we need to set the plain_modulus to be a prime number
    congruent to 1 modulo 2*poly_modulus_degree. Microsoft SEAL provides a helper
    method for finding such a prime. In this example we create a 20-bit prime
    that supports batching. */
	params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	auto context = SEALContext::Create(params);
	print_parameters(context);
	cout << endl;


}

int main()
{
	bfvdemo();
	// integerEncoderDemo();
	// batchEncoderDemo();
	return 0;
}
