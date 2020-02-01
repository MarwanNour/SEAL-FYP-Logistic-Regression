#include "seal/seal.h"
#include <iostream>
#include <iomanip>
#include <vector>

#include "seal/seal.h"


using namespace std;
using namespace seal;

// Helper function that prints a matrix
template <typename T>
void print_matrix(vector<T> matrix, size_t row_size)
{

    size_t print_size = 5;

    cout << "\t[";
    for (size_t i = 0; i < print_size; i++)
    {
        cout << matrix[i] << ", ";
    }
    cout << "...,";

    for (size_t i = row_size - print_size; i < row_size; i++)
    {
        cout << matrix[i]
             << ((i != row_size - 1) ? ", " : " ]\n");
    }
    cout << "\t[";
    for (size_t i = row_size; i < row_size + print_size; i++)
    {
        cout << matrix[i] << ", ";
    }
    cout << "...,";
    for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        cout << matrix[i]
             << ((i != 2 * row_size - 1) ? ", " : " ]\n");
    }
    cout << endl;
}

// Helper function that prints a vector of floats
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

void integerEncoding()
{
    cout << "\n--------- Integer Encoding ---------\n"
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
    cout << "\t+ NOISE budget in cipher1: " << decryptor.invariant_noise_budget(cipher1) << " bits" << endl;
    cout << "\t+ NOISE budget in cipher2: " << decryptor.invariant_noise_budget(cipher2) << " bits" << endl;

    // Example: Compute (cipher1*cipher2) - cipher1
    Ciphertext cipherResult;
    cout << "\nComputing (cipher1*cipher2) - cipher1:" << endl;
    Ciphertext cipher1_mul_cipher2;
    evaluator.multiply(cipher1, cipher2, cipher1_mul_cipher2);
    evaluator.sub(cipher1_mul_cipher2, cipher1, cipherResult);
    cout << "\t+ NOISE budget in cipherResult: " << decryptor.invariant_noise_budget(cipherResult) << " bits" << endl;

    // Decrypt
    Plaintext plain_result;
    decryptor.decrypt(cipherResult, plain_result);
    cout << "Decrypted plaintext result:\n\t" << plain_result.to_string() << endl;

    // Decode
    cout << "Decoded Result:\n\t" << encoder.decode_int32(plain_result) << endl;
}

void batchEncoding()
{
    cout << "\n--------- Batch Encoding ---------\n"
         << endl;

    // Set the parameters
    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Plain modulus in batching is a prime number congruent to: 1 mod 2*poly_modulus_degree.
    // SEAL provides a helper function for it
    // Creating a 20 bit prime
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    auto context = SEALContext::Create(params);

    auto qualifiers = context->first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create BatchEncoder
    BatchEncoder batch_encoder(context);

    // In BFV the number of slots is equal to poly_modulus_degree
    // and they are arranged into a matrix with 2 rows
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext Matrix row size: " << row_size << endl;

    // Create first matrix
    vector<uint64_t> matrix1(slot_count, 0);
    matrix1[0] = 0;
    matrix1[1] = 1;
    matrix1[2] = 2;
    matrix1[3] = 3;
    matrix1[row_size] = 4;
    matrix1[row_size + 1] = 5;
    matrix1[row_size + 2] = 6;
    matrix1[row_size + 3] = 7;

    cout << "First Input plaintext matrix:" << endl;

    // Print the matrix
    print_matrix(matrix1, row_size);

    // Encode  the matrix into a plaintext polynomial
    Plaintext plaint_matrix1;
    cout << "Encoded plaintext matrix:" << endl;
    batch_encoder.encode(matrix1, plaint_matrix1);

    // Encrypt the encoded matrix
    Ciphertext cipher_matrix1;
    cout << "Encrypt plaint_matrix1 to cipher_matrix: " << endl;
    encryptor.encrypt(plaint_matrix1, cipher_matrix1);

    cout << "\t+ NOISE budget in cipher_matrix: " << decryptor.invariant_noise_budget(cipher_matrix1) << " bits" << endl;

    // Create second matrix
    vector<uint64_t> matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        matrix2.push_back((i % 2) + 1);
    }
    cout << "\nSecond input plaintext matrix: " << endl;
    print_matrix(matrix2, row_size);

    Plaintext plain_matrix2;
    batch_encoder.encode(matrix2, plain_matrix2);

    // Compute (cipher_matrix1 + plain_matrix2)^2
    cout << "Computing (cipher_matrix1 + plain_matrix2)^2" << endl;
    cout << "Sum, square and relinearize" << endl;
    evaluator.add_plain_inplace(cipher_matrix1, plain_matrix2);
    evaluator.square_inplace(cipher_matrix1);
    evaluator.relinearize_inplace(cipher_matrix1, relin_keys);

    cout << "\t+ NOISE budget in result: " << decryptor.invariant_noise_budget(cipher_matrix1) << " bits" << endl;

    // Decrypt and Decode
    Plaintext plain_result;
    cout << "Decrypt and Decode the result" << endl;
    decryptor.decrypt(cipher_matrix1, plain_result);
    vector<uint64_t> matrix_result;
    batch_encoder.decode(plain_result, matrix_result);
    print_matrix(matrix_result, row_size);
}

void ckksEncoding()
{
    cout << "\n--------- CKKS Encoding ---------\n"
         << endl;

    // Set the parameters
    EncryptionParameters params(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    // CKKS doesn't require a plain_modulus
    // Generating 5 40bit prime numbers for CoeffModulus
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40}));

    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    // Create CKKSEncoder
    CKKSEncoder ckks_encoder(context);

    // In CKKS the number of slots is poly_modulus_degree / 2
    size_t slot_count = ckks_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input_vec{0.0, 1.1, 2.2, 3.3};
    cout << "Input vector: " << endl;

    // print vector
    print_vector(input_vec);

    // Encode the vector
    Plaintext plain_vec;
    double scale = pow(2.0, 30); // scale is used like a precision parameter
    cout << "Encode input_vec" << endl;
    ckks_encoder.encode(input_vec, scale, plain_vec);

    // Encrypt
    Ciphertext cipher_vec;
    encryptor.encrypt(plain_vec, cipher_vec);

    // Squaring the cipher_vec
    evaluator.square_inplace(cipher_vec);
    evaluator.relinearize_inplace(cipher_vec, relin_keys);

    cout << "\t+ Scale in cipher_vec: " << cipher_vec.scale()
         << " (" << log2(cipher_vec.scale()) << " bits)" << endl;

    cout << "Decrypt and Decode cipher_vec" << endl;
    decryptor.decrypt(cipher_vec, plain_vec);
    vector<double> output_vec;
    ckks_encoder.decode(plain_vec, output_vec);
    print_vector(output_vec);
}

int main()
{

    integerEncoding();
    batchEncoding();
    ckksEncoding();
    return 0;
}