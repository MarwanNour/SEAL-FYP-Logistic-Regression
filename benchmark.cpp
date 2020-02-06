#include <iostream>
#include <fstream>
#include <iomanip>
#include "seal/seal.h"

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

void ckksBenchmark()
{
    cout << "------CKKS TEST------\n"
         << endl;

    // Set params
    EncryptionParameters params(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "Slot count : " << slot_count << endl;
    // First vector
    vector<double> pod_vec1(slot_count, 0);
    for (unsigned int i = 0; i < slot_count; i++)
    {
        pod_vec1[i] = static_cast<double>(i);
    }

    print_vector(pod_vec1);

    // Second vector
    vector<double> pod_vec2(slot_count, 0);
    for (unsigned int i = 0; i < slot_count; i++)
    {
        pod_vec2[i] = static_cast<double>((i % 2) + 1);
    }

    print_vector(pod_vec2);

    // Encode the pod_vec1 and pod_vec2

    Plaintext plain_vec1, plain_vec2;
    // Scale used here sqrt of last coeff modulus
    double scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));
    ckks_encoder.encode(pod_vec1, scale, plain_vec1);
    ckks_encoder.encode(pod_vec2, scale, plain_vec2);

    // Encrypt plain_vec1
    cout << "Encrypt plain_vec1 to cipher_vec1:" << endl;
    Ciphertext cipher_vec1;
    encryptor.encrypt(plain_vec1, cipher_vec1);
    // cout << "\t+ NOISE budget in cipher_vec1: " << decryptor.invariant_noise_budget(cipher_vec1) << " bits" << endl;

    // Compute (cipher_vec1 + plain_vec2)^2
    cout << "Computing (cipher_vec1 + plain_vec2)^2" << endl;

    // TIME START
    auto start = chrono::high_resolution_clock::now();

    evaluator.add_plain_inplace(cipher_vec1, plain_vec2);
    evaluator.square_inplace(cipher_vec1);
    evaluator.relinearize_inplace(cipher_vec1, relin_keys);

    // TIME END
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);

    // cout << "\t+ NOISE budget in result: " << decryptor.invariant_noise_budget(cipher_vec1) << " bits" << endl;

    // Decrypt and Decode
    Plaintext plain_result;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_vec1, plain_result);
    vector<double> vec_result;
    ckks_encoder.decode(plain_result, vec_result);
    print_vector(vec_result);

    cout << "\nTime to compute (cipher_vec1 + plain_vec2)^2 :" << duration.count() << " microseconds" << endl;
}

int main()
{

    // Need to plot graph with x-axis as the size and y-axis as the duration
    // Plot 3 different graphs (with 3 different ploy_modulus_degree)
    EncryptionParameters params(scheme_type::CKKS);

    // Case 1 : poly_modulus_degree = 4096
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Run the tests

    // Set output file
    string filename_1 = "bench_4096.dat";
    ofstream outf_1(filename_1);
    // Handle file error
    if (!outf_1)
    {
        cerr << "Couldn't open file: " << filename_1 << endl;
        exit(1);
    }

    // Write to file
    outf_1 << "2"
         << "\t\t"
         << "230" << endl;
    outf_1 << "3"
         << "\t\t"
         << "400" << endl;
    outf_1 << "5"
         << "\t\t"
         << "230" << endl;
    outf_1 << "6"
         << "\t\t"
         << "400" << endl;

    // Close the file
    outf_1.close();

    // Case 2 : poly_modulus_degree = 8192
    poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Run the tests

    // Set output file
    string filename_2 = "bench_8192.dat";
    ofstream outf_2(filename_2);
    // Handle file error
    if (!outf_2)
    {
        cerr << "Couldn't open file: " << filename_2 << endl;
        exit(1);
    }

    // Write to file
    outf_2 << "2"
         << "\t\t"
         << "230" << endl;
    outf_2 << "3"
         << "\t\t"
         << "400" << endl;
    outf_2 << "5"
         << "\t\t"
         << "230" << endl;
    outf_2 << "6"
         << "\t\t"
         << "400" << endl;

    // Close the file
    outf_2.close();

    // Case 3 : poly_modulus_degree = 16384
    poly_modulus_degree = 16384;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Run the tests

    // Set output file
    string filename_3 = "bench_16384.dat";
    ofstream outf_3(filename_3);
    // Handle file error
    if (!outf_3)
    {
        cerr << "Couldn't open file: " << filename_3 << endl;
        exit(1);
    }

    // Write to file
    outf_3 << "2"
         << "\t\t"
         << "230" << endl;
    outf_3 << "3"
         << "\t\t"
         << "400" << endl;
    outf_3 << "5"
         << "\t\t"
         << "230" << endl;
    outf_3 << "6"
         << "\t\t"
         << "400" << endl;

    // Close the file
    outf_3.close();

    return 0;
}
