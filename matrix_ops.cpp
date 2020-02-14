#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper function that prints a matrix (vector of vectors)
template <typename T>
inline void print_full_matrix(vector<vector<T>> matrix, int precision = 3)
{
    // save formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);
    int row_size = matrix.size();
    int col_size = matrix[0].size();
    for (unsigned int i = 0; i < row_size; i++)
    {
        cout << "[";
        for (unsigned int j = 0; j < col_size - 1; j++)
        {
            cout << matrix[i][j] << ", ";
        }
        cout << matrix[i][col_size - 1];
        cout << "]" << endl;
    }
    cout << endl;
    // restore old cout formatting
    cout.copyfmt(old_fmt);
}

// Helper function that prints parts of a matrix (only squared matrix)
template <typename T>
inline void print_partial_matrix(vector<vector<T>> matrix, int print_size = 3, int precision = 3)
{
    // save formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);

    int row_size = matrix.size();
    int col_size = matrix[0].size();

    // Boundary check
    if (row_size < 2 * print_size && col_size < 2 * print_size)
    {
        cerr << "Cannot print matrix with these dimensions: " << to_string(row_size) << "x" << to_string(col_size) << ". Increase the print size" << endl;
        return;
    }
    // print first 4 elements
    for (unsigned int row = 0; row < print_size; row++)
    {
        cout << "\t[";
        for (unsigned int col = 0; col < print_size; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << "..., ";
        for (unsigned int col = col_size - print_size; col < col_size - 1; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << matrix[row][col_size - 1];
        cout << "]" << endl;
    }
    cout << "\t..." << endl;

    for (unsigned int row = row_size - print_size; row < row_size; row++)
    {
        cout << "\t[";
        for (unsigned int col = 0; col < print_size; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << "..., ";
        for (unsigned int col = col_size - print_size; col < col_size - 1; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << matrix[row][col_size - 1];
        cout << "]" << endl;
    }

    cout << endl;
    // restore old cout formatting
    cout.copyfmt(old_fmt);
}

void slowEncoding(int dimension)
{
    cout << "Dimension :" << dimension << endl
         << endl;
    EncryptionParameters params(scheme_type::CKKS);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create scale
    double scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));

    // Create Input matrices
    vector<vector<double>> pod_matrix1(dimension, vector<double>(dimension));
    vector<vector<double>> pod_matrix2(dimension, vector<double>(dimension));

    // Fill input matrices
    double k = 0.0;
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix1[i][j] = k;
            pod_matrix2[i][j] = static_cast<double>((j % 2) + 1);
            k++;
        }
    }
    print_partial_matrix(pod_matrix1);

    print_partial_matrix(pod_matrix2);

    // Encode matrices
    vector<vector<Plaintext>> plain_matrix1(dimension, vector<Plaintext>(dimension));
    vector<vector<Plaintext>> plain_matrix2(dimension, vector<Plaintext>(dimension));

    auto start_encode = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            ckks_encoder.encode(pod_matrix1[i][j], scale, plain_matrix1[i][j]);
            ckks_encoder.encode(pod_matrix2[i][j], scale, plain_matrix2[i][j]);
        }
    }

    auto stop_encode = chrono::high_resolution_clock::now();
    auto duration_encode = chrono::duration_cast<chrono::microseconds>(stop_encode - start_encode);

    cout << "Encoding time: " << duration_encode.count() << " microseconds" << endl;

    // Encrypt the matrices
    vector<vector<Ciphertext>> cipher_matrix1(dimension, vector<Ciphertext>(dimension));
    vector<vector<Ciphertext>> cipher_matrix2(dimension, vector<Ciphertext>(dimension));

    auto start_encrypt = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            encryptor.encrypt(plain_matrix1[i][j], cipher_matrix1[i][j]);
            encryptor.encrypt(plain_matrix2[i][j], cipher_matrix2[i][j]);
        }
    }
    auto stop_encrypt = chrono::high_resolution_clock::now();
    auto duration_encrypt = chrono::duration_cast<chrono::microseconds>(stop_encrypt - start_encrypt);

    cout << "Encryption time: " << duration_encrypt.count() << " microseconds" << endl;

    // C1+P2
    cout << "\n----------------- C1 + P2----------------\n"
         << endl;

    vector<vector<Ciphertext>> cipher_result_addition_plain(dimension, vector<Ciphertext>(dimension));

    auto start_add_plain = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            evaluator.add_plain(cipher_matrix1[i][j], plain_matrix2[i][j], cipher_result_addition_plain[i][j]);
        }
    }

    auto stop_add_plain = chrono::high_resolution_clock::now();
    auto duration_add_plain = chrono::duration_cast<chrono::microseconds>(stop_add_plain - start_add_plain);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_plain(dimension, vector<Plaintext>(dimension));

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain[i][j], plain_result_addition_plain[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_plain(dimension, vector<double>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_plain[i][j], temp);
            pod_result_addition_plain[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_plain);

    cout << "Compute C1+P2 time : " << duration_add_plain.count() << " microseconds" << endl;


    // C1+C2
    cout << "\n----------------- C1 + C2----------------\n"
         << endl;

    vector<vector<Ciphertext>> cipher_result_addition_cipher(dimension, vector<Ciphertext>(dimension));

    auto start_add_cipher = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            evaluator.add(cipher_matrix1[i][j], cipher_matrix2[i][j], cipher_result_addition_cipher[i][j]);
        }
    }

    auto stop_add_cipher = chrono::high_resolution_clock::now();
    auto duration_add_cipher = chrono::duration_cast<chrono::microseconds>(stop_add_cipher - start_add_cipher);

    // Decrypt 
    vector<vector<Plaintext>> plain_result_addition_cipher(dimension, vector<Plaintext>(dimension));

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain[i][j], plain_result_addition_cipher[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_cipher(dimension, vector<double>(dimension));
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_cipher[i][j], temp);
            pod_result_addition_cipher[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_cipher);

    cout << "Compute C1+C2 time : " << duration_add_cipher.count() << " microseconds" << endl;

/*
    // C1+P2
    cout << "\n----------------- C1 * P2 (component-wise)----------------\n"
         << endl;

    vector<vector<Ciphertext>> cipher_result_mult_plain(dimension, vector<Ciphertext>(dimension));

    auto start_mult_plain = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            evaluator.multiply_plain(cipher_matrix1[i][j], plain_matrix2[i][j], cipher_result_mult_plain[i][j]);
        }
    }

    auto stop_mult_plain = chrono::high_resolution_clock::now();
    auto duration_mult_plain = chrono::duration_cast<chrono::microseconds>(stop_mult_plain - start_mult_plain);

    cout << "Compute C1 * P2 (component-wise) time : " << duration_mult_plain.count() << " microseconds" << endl;
    */
}

int main()
{
    slowEncoding(10);

    return 0;
}