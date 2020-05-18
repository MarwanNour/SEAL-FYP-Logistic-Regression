#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "helper.h"

using namespace std;
using namespace seal;

void MatrixTranspose(size_t poly_modulus_degree, int dimension)
{
    // Handle Rotation Error First
    if (dimension > poly_modulus_degree / 4)
    {
        cerr << "Dimension is too large. Choose a dimension less than " << poly_modulus_degree / 4 << endl;
        exit(1);
    }

    EncryptionParameters params(scheme_type::CKKS);
    params.set_poly_modulus_degree(poly_modulus_degree);
    cout << "MAX BIT COUNT: " << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 60}));
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    GaloisKeys gal_keys = keygen.galois_keys();
    RelinKeys relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);

    // Create Scale
    double scale = pow(2.0, 40);

    int dimensionSq = pow(dimension, 2);

    // Create input matrix
    vector<vector<double>> pod_matrix1_set1(dimension, vector<double>(dimension));

    // Fill input matrices
    // double r = ((double)rand() / (RAND_MAX));
    double filler = 1;
    // Matrix 1
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            filler++;
            // r = ((double)rand() / (RAND_MAX));
        }
    }

    cout << "Matrix 1:" << endl;
    print_full_matrix(pod_matrix1_set1, 0);

    // Get U_tranposed
    vector<vector<double>> U_transposed = get_U_transpose(pod_matrix1_set1);

    cout << "\nU_tranposed:" << endl;
    print_full_matrix(U_transposed, 0);

    // Get diagonals for U_transposed
    vector<vector<double>> U_transposed_diagonals = get_all_diagonals(U_transposed);

    // Test ADD EPSILON
    double epsilon = 0.00000001;
    for (int i = 0; i < dimensionSq; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            U_transposed_diagonals[i][j] += epsilon;
        }
    }

    // --------------- ENCODING ----------------
    // Encode U_transposed_diagonals
    vector<Plaintext> U_transposed_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_tranposed_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_transposed_diagonals[i], scale, U_transposed_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    cout << "\nEncoding Matrix 1...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- ENCRYPTING ----------------
    // Encrypt Matrix 1
    vector<Ciphertext> cipher_matrix1_set1(dimension);
    cout << "\nEncrypting Matrix 1...";

    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    cout << "\nMatrix Encoding Matrix 1...";
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, evaluator);
    cout << "Done" << endl;

    // --------------- MATRIX TRANSPOSING ----------------
    cout << "\nMatrix Transposition...";
    Ciphertext ct_result = Linear_Transform_Plain(cipher_encoded_matrix1_set1, U_transposed_diagonals_plain, gal_keys, params);
    cout << "Done" << endl;

    // --------------- DECRYPT ----------------
    Plaintext pt_result;
    cout << "\nResult Decrypt...";
    decryptor.decrypt(ct_result, pt_result);
    cout << "Done" << endl;

    // --------------- DECODE ----------------
    vector<double> result_matrix;
    cout << "\nResult Decode...";
    ckks_encoder.decode(pt_result, result_matrix);
    cout << "Done" << endl;

    // print_partial_vector(result_matrix, result_matrix.size());
    cout << "Resulting matrix: ";
    for (int i = 0; i < dimensionSq; i++)
    {
        if (i % dimension == 0)
        {
            cout << "\n\t";
        }
        cout << result_matrix[i] << ", ";
    }
    cout << endl;

    // Test Matrix DECODE
    cout << "\nMATRIX DECODING... ";
    vector<Ciphertext> ct_decoded_vec = C_Matrix_Decode(ct_result, dimension, scale, gal_keys, ckks_encoder, evaluator);
    cout << "Done" << endl;

    // DECRYPT and DECODE
    vector<Plaintext> pt_decoded_vec(dimension);
    for (int i = 0; i < dimension; i++)
    {
        decryptor.decrypt(ct_decoded_vec[i], pt_decoded_vec[i]);
        vector<double> decoded_vec;
        ckks_encoder.decode(pt_decoded_vec[i], decoded_vec);
        cout << "\t[";
        for (int j = 0; j < dimension; j++)
        {
            cout << decoded_vec[j] << ", ";
        }
        cout << "]" << endl;
    }

    // Dummy Diagonal test
    cout << "\n----------------DUMMY TEST-----------------\n"
         << endl;
    int coldim = 4;
    int rowdim = 3;
    vector<vector<double>> dummy_matrix(rowdim, vector<double>(coldim));
    vector<double> row_0 = {1, 2, 3, 4};
    vector<double> row_1 = {5, 6, 7, 8};
    vector<double> row_2 = {9, 10, 11, 12};

    dummy_matrix[0] = row_0;
    dummy_matrix[1] = row_1;
    dummy_matrix[2] = row_2;

    cout << "Dummy matrix:" << endl;
    print_full_matrix(dummy_matrix);

    vector<vector<double>> dummy_diagonals = get_all_diagonals(dummy_matrix);
    cout << "\nDummy matrix diagonals:" << endl;

    print_full_matrix(dummy_diagonals);

    // cout << "\nTransposed dummy matrix diagonals:" << endl;
    // vector<vector<double>> tranposed_diag = transpose_matrix(dummy_diagonals);
    // print_full_matrix(tranposed_diag);

    // cout << "\n\nTransposed dummy matrix:" << endl;
    // vector<vector<double>> tranposed_dummy = transpose_matrix(dummy_matrix);
    // print_full_matrix(tranposed_dummy);

    // cout << "\nDiagonals of Transposed dummy:" << endl;
    // vector<vector<double>> diag_tranposed_dummy = get_all_diagonals(tranposed_dummy);
    // print_full_matrix(diag_tranposed_dummy);

    // TEST DOT PRODUCT
    Plaintext pt_0;
    ckks_encoder.encode(row_0, scale, pt_0);
    Plaintext pt_1;
    ckks_encoder.encode(row_1, scale, pt_1);

    Ciphertext ct_0;
    encryptor.encrypt(pt_0, ct_0);
    Ciphertext ct_1;
    encryptor.encrypt(pt_1, ct_1);

    Ciphertext dot_prod_ct = cipher_dot_product(ct_0, ct_1, 4, relin_keys, gal_keys, evaluator);

    Plaintext dot_prod_pt;
    decryptor.decrypt(dot_prod_ct, dot_prod_pt);
    vector<double> dot_prod;
    ckks_encoder.decode(dot_prod_pt, dot_prod);

    cout << "\n\n DOT PROD:" << endl;
    for (int i = 0; i < 10; i++)
    {
        cout << dot_prod[i] << ", ";
    }
    cout << "\n"
         << endl;
}

int main()
{
    MatrixTranspose(8192 * 2, 4);

    return 0;
}