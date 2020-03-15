#include "fyp_helper.h"

// Ops in BFV
void bfvOps()
{
    cout << "------BFV TEST------\n"
         << endl;

    // Set the parameters
    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(786433);
    auto context = SEALContext::Create(params);

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
    for (unsigned int i = 0; i < slot_count; i++)
    {
        matrix1[i] = i;
    }

    cout << "First Input plaintext matrix:" << endl;

    // Print the matrix
    print_matrix(matrix1, row_size);

    // Encode  the matrix into a plaintext polynomial
    Plaintext plaint_matrix1;
    cout << "Encode plaintext matrix" << endl;
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

    // TIME START
    auto start = chrono::high_resolution_clock::now();

    evaluator.add_plain_inplace(cipher_matrix1, plain_matrix2);
    evaluator.square_inplace(cipher_matrix1);
    evaluator.relinearize_inplace(cipher_matrix1, relin_keys);

    // TIME END
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);

    cout << "\t+ NOISE budget in result: " << decryptor.invariant_noise_budget(cipher_matrix1) << " bits" << endl;

    // Decrypt and Decode
    Plaintext plain_result;
    cout << "Decrypt and Decode the result" << endl;
    decryptor.decrypt(cipher_matrix1, plain_result);
    vector<uint64_t> matrix_result;
    batch_encoder.decode(plain_result, matrix_result);
    print_matrix(matrix_result, row_size);

    cout << "\nTime to compute (cipher_matrix1 + plain_matrix2)^2 :" << duration.count() << " microseconds" << endl;
}

// Ops in CKKS
void ckksOps()
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

    /* In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
    one real or complex number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree
    and they are arranged into a matrix with two rows. */
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
    bfvOps();
    ckksOps();

    return 0;
}