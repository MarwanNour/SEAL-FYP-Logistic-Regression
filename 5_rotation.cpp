#include "seal/seal.h"
#include <iostream>
#include <iomanip>

using namespace std;
using namespace seal;

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

void bfvRotation()
{
    cout << "---------- Rotations in BFV -----------\n"
         << endl;
    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    auto context = SEALContext::Create(params);

    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    size_t row_size = slot_count / 2;

    cout << "Plaintext Matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    Plaintext plain_matrix;
    cout << "\nEncode and encrypt: " << endl;
    encoder.encode(pod_matrix, plain_matrix);
    Ciphertext cipher_matrix;
    encryptor.encrypt(plain_matrix, cipher_matrix);
    cout << "\t+ NOISE budget in cipher_matrix: " << decryptor.invariant_noise_budget(cipher_matrix) << " bits" << endl;

    GaloisKeys gal_keys = keygen.galois_keys();

    // Rotate matrix rows 3 steps to the left
    cout << "\nRotate rows 3 steps left:" << endl;
    evaluator.rotate_rows_inplace(cipher_matrix, 3, gal_keys);
    cout << "\t+ NOISE budget after rotations: " << decryptor.invariant_noise_budget(cipher_matrix) << " bits" << endl;
    cout << "\t+ Decrypt and decode: " << endl;
    Plaintext plain_result;

    decryptor.decrypt(cipher_matrix, plain_result);
    encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // Rotate columns (swap rows)
    cout << "\nRotate Columns (Swap the rows:" << endl;
    evaluator.rotate_columns_inplace(cipher_matrix, gal_keys);
    cout << "\t+ NOISE budget after rotations: " << decryptor.invariant_noise_budget(cipher_matrix) << " bits" << endl;
    cout << "\t+ Decrypt and decode: " << endl;
    decryptor.decrypt(cipher_matrix, plain_result);
    encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // Rotate the rows 4 steps to the right
    cout << "\nRotate rows 4 steps right: " << endl;
    evaluator.rotate_rows_inplace(cipher_matrix, -4, gal_keys);
    cout << "\t+ NOISE budget after rotations: " << decryptor.invariant_noise_budget(cipher_matrix) << " bits" << endl;
    cout << "\t+ Decrypt and decode: " << endl;
    decryptor.decrypt(cipher_matrix, plain_result);
    encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);
}

void ckksRotation()
{
    cout << "---------- Rotations in CKKS -----------\n"
         << endl;
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {40, 40, 40, 40, 40}));

    auto context = SEALContext::Create(parms);
    cout << endl;

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50);

    cout << "Encode and encrypt." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    Ciphertext rotated;
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted, 2, gal_keys, rotated);
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    ckks_encoder.decode(plain, result);
    print_vector(result, 3, 7);
}

int main()
{
    bfvRotation();
    ckksRotation();

    return 0;
}