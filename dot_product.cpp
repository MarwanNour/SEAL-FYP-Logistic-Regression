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

// Gets a diagonal from a matrix U
template <typename T>
vector<T> get_diagonal(int position, vector<vector<T>> U)
{

    vector<T> diagonal(U.size());

    int k = 0;
    // U(0,l) , U(1,l+1), ... ,  U(n-l-1, n-1)
    for (int i = 0, j = position; (i < U.size() - position) && (j < U.size()); i++, j++)
    {
        diagonal[k] = U[i][j];
        k++;
    }
    for (int i = U.size() - position, j = 0; (i < U.size()) && (j < position); i++, j++)
    {
        diagonal[k] = U[i][j];
        k++;
    }

    return diagonal;
}

Ciphertext Linear_Transform(Ciphertext ct, vector<Plaintext> U_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{
    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    // Fill ct with duplicate
    Ciphertext ct_rot;
    evaluator.rotate_vector(ct, -U_diagonals.size(), gal_keys, ct_rot);
    cout << "U_diagonals.size() = " << U_diagonals.size() << endl;
    Ciphertext ct_new;
    evaluator.add(ct, ct_rot, ct_new);

    vector<Ciphertext> ct_result(U_diagonals.size());
    evaluator.multiply_plain(ct_new, U_diagonals[0], ct_result[0]);

    for (int l = 1; l < U_diagonals.size(); l++)
    {
        Ciphertext temp_rot;
        evaluator.rotate_vector(ct_new, l, gal_keys, temp_rot);
        evaluator.multiply_plain(temp_rot, U_diagonals[l], ct_result[l]);
    }
    Ciphertext ct_prime;
    evaluator.add_many(ct_result, ct_prime);

    return ct_prime;
}

void dotProd(size_t poly_modulus_degree)
{
    EncryptionParameters params(scheme_type::CKKS);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    GaloisKeys gal_keys = keygen.galois_keys();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);
    // Create scale
    cout << "Coeff Modulus Back Value: " << params.coeff_modulus().back().value() << endl;
    double scale = static_cast<double>(sqrt(params.coeff_modulus().back().value()));

    int dimension1 = 8;
    cout << "Dimension Set 1: " << dimension1 << endl
         << endl;

    vector<vector<double>> pod_matrix1_set1(dimension1, vector<double>(dimension1));
    vector<vector<double>> pod_matrix2_set1(dimension1, vector<double>(dimension1));

    // Fill input matrices
    double filler = 1.0;
    // Set 1
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            pod_matrix2_set1[i][j] = static_cast<double>((j % 2) + 1);
            filler++;
        }
    }
    print_full_matrix(pod_matrix1_set1);
    print_full_matrix(pod_matrix2_set1);

    vector<double> diagonal_matrix1_0 = get_diagonal(0, pod_matrix1_set1);

    cout << "\n\t[";
    for (int i = 0; i < diagonal_matrix1_0.size() - 1; i++)
    {
        cout << diagonal_matrix1_0[i] << ", ";
    }
    cout << diagonal_matrix1_0[diagonal_matrix1_0.size() - 1];
    cout << "]\n"
         << endl;

    // Get all diagonals
    vector<vector<double>> all_diagonal_1(dimension1, vector<double>(dimension1));
    vector<vector<double>> all_diagonal_2(dimension1, vector<double>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        all_diagonal_1[i] = get_diagonal(i, pod_matrix1_set1);
        all_diagonal_2[i] = get_diagonal(i, pod_matrix2_set1);
    }

    cout << "Diagonal Set 1 Expected:" << endl;
    for (int i = 0; i < dimension1; i++)
    {
        cout << "\t[";
        for (int j = 0; j < dimension1 - 1; j++)
        {
            cout << all_diagonal_1[i][j] << ", ";
        }
        cout << all_diagonal_1[i][dimension1 - 1];
        cout << "]" << endl;
    }
    cout << "\n"
         << endl;

    // Encode Matrices into vectors with Diagonals
    vector<Plaintext> plain_matrix1_set1(dimension1), plain_matrix2_set1(dimension1);
    vector<Plaintext> plain_diagonal1_set1(dimension1), plain_diagonal2_set1(dimension1);

    for (int i = 0; i < dimension1; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
        ckks_encoder.encode(pod_matrix2_set1[i], scale, plain_matrix2_set1[i]);
        ckks_encoder.encode(all_diagonal_1[i], scale, plain_diagonal1_set1[i]);
        ckks_encoder.encode(all_diagonal_2[i], scale, plain_diagonal2_set1[i]);
    }

    cout << "Encoding is Complete" << endl;

    // Encrypt the matrices with Diagonals
    vector<Ciphertext> cipher_matrix1_set1(dimension1), cipher_matrix2_set1(dimension1);
    vector<Ciphertext> cipher_diagonal1_set1(dimension1), cipher_diagonal2_set1(dimension1);

    // First set cipher
    for (unsigned int i = 0; i < dimension1; i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
        encryptor.encrypt(plain_diagonal1_set1[i], cipher_diagonal1_set1[i]);
        encryptor.encrypt(plain_diagonal2_set1[i], cipher_diagonal2_set1[i]);
    }
    cout << "Encrypting is Complete" << endl;

    // test decrypt here
    for (unsigned int i = 0; i < dimension1; i++)
    {
        decryptor.decrypt(cipher_matrix1_set1[i], plain_matrix1_set1[i]);
        decryptor.decrypt(cipher_matrix2_set1[i], plain_matrix2_set1[i]);
        decryptor.decrypt(cipher_diagonal1_set1[i], plain_diagonal1_set1[i]);
        decryptor.decrypt(cipher_diagonal2_set1[i], plain_diagonal2_set1[i]);
    }

    // test decode here
    // test decrypt here
    for (unsigned int i = 0; i < dimension1; i++)
    {
        ckks_encoder.decode(plain_diagonal1_set1[i], all_diagonal_1[i]);
        ckks_encoder.decode(plain_diagonal2_set1[i], all_diagonal_2[i]);
    }

    // test print output
    cout << "\nDiagonal Set 1 Result:" << endl;
    for (unsigned int i = 0; i < dimension1; i++)
    {
        cout << "\t[";
        for (unsigned int j = 0; j < dimension1 - 1; j++)
        {
            cout << all_diagonal_1[i][j] << ", ";
        }
        cout << all_diagonal_1[i][dimension1 - 1];
        cout << "]" << endl;
    }
    cout << "\n"
         << endl;

    // Create ciphertext output
    // Set 1 output
    // vector<Ciphertext> cipher_result1_set1(dimension1), cipher_result2_set1(dimension1), cipher_result3_set1(dimension1), cipher_result4_set1(dimension1);

    // Test LinearTransform here
    // Ciphertext ct_prime = Linear_Transform(cipher_matrix1_set1[0], plain_diagonal1_set1, gal_keys, params);

    // Fill ct
    Ciphertext ct_rotated;
    evaluator.rotate_vector(cipher_matrix1_set1[0], -dimension1, gal_keys, ct_rotated);
    Ciphertext ct;
    evaluator.add(cipher_matrix1_set1[0], ct_rotated, ct);

    // Add epsilon to avoid negative numbers
    vector<double> epsilon_vec(poly_modulus_degree / 2);
    for (int i = 0; i < epsilon_vec.size(); i++)
    {
        epsilon_vec[i] = 0.0000;
    }
    Plaintext epsilon_plain;
    ckks_encoder.encode(epsilon_vec, scale, epsilon_plain);
    evaluator.add_plain_inplace(ct, epsilon_plain);

    // test fill ct
    Plaintext test_fill;
    decryptor.decrypt(ct, test_fill);
    vector<double> out_fill;
    ckks_encoder.decode(test_fill, out_fill);
    cout << "Filled CT:\n"
         << endl;
    for (int i = 0; i < dimension1; i++)
    {
        cout << out_fill[i] << ", ";
    }
    cout << "\n"
         << endl;

    Ciphertext ct_prime;
    // ct` = CMult(ct, u0)
    evaluator.multiply_plain(ct, plain_diagonal1_set1[0], ct_prime);

    // test mult plain 0
    Plaintext test_0;
    decryptor.decrypt(ct_prime, test_0);
    vector<double> out_test_0;
    ckks_encoder.decode(test_0, out_test_0);
    cout << "CT_Prime 0 :\n"
         << endl;
    for (int i = 0; i < dimension1; i++)
    {
        cout << out_test_0[i] << ", ";
    }
    cout << "\n"
         << endl;

    for (int l = 1; l < dimension1; l++)
    {
        // ct` = Add(ct`, CMult(Rot(ct, l), ul))
        Ciphertext temp_rot;
        Ciphertext temp_mul;
        evaluator.rotate_vector(ct, l, gal_keys, temp_rot);
        evaluator.multiply_plain(temp_rot, plain_diagonal1_set1[l], temp_mul);
        evaluator.add_inplace(ct_prime, temp_mul);

        // test decrypt
        Plaintext temp_rot_plain;
        Plaintext temp_mul_plain;
        Plaintext temp_ct_prime;

        decryptor.decrypt(temp_rot, temp_rot_plain);
        decryptor.decrypt(temp_mul, temp_mul_plain);
        decryptor.decrypt(ct_prime, temp_ct_prime);

        // test decode
        vector<double> test_out_rot, test_out_mul, test_ct_prime;
        vector<double> test_diag;
        ckks_encoder.decode(temp_ct_prime, test_ct_prime);
        ckks_encoder.decode(temp_mul_plain, test_out_mul);
        ckks_encoder.decode(temp_rot_plain, test_out_rot);
        ckks_encoder.decode(plain_diagonal1_set1[l], test_diag);

        cout << "Rotation " << l << "\n"
             << endl;
        cout << "\nrotated vec:\n\t[";
        for (int j = 0; j < dimension1; j++)
        {
            cout << test_out_rot[j] << ", ";
        }
        cout << "\nDiagonal vec:\n\t[";
        for (int j = 0; j < dimension1; j++)
        {
            cout << test_diag[j] << ", ";
        }
        cout << "\nMult vec vec:\n\t[";

        for (int j = 0; j < dimension1; j++)
        {
            cout << test_out_mul[j] << ", ";
        }
        cout << "\nCt_prime vec:\n\t[";

        for (int j = 0; j < dimension1; j++)
        {
            cout << test_ct_prime[j] << ", ";
        }
        cout << "\n"
             << endl;
    }

    // Decrypt
    Plaintext pt_result;
    decryptor.decrypt(ct_prime, pt_result);

    // Decode
    vector<double> output_result;
    ckks_encoder.decode(pt_result, output_result);

    cout << "Linear Transformation Result:" << endl;
    cout << "\t[";
    for (int i = 0; i < dimension1 - 1; i++)
    {
        cout << output_result[i] << ", ";
    }
    cout << output_result[dimension1 - 1];

    cout << "]" << endl;

    // test decrypt
    Plaintext test_cipher;
    decryptor.decrypt(cipher_matrix1_set1[0], test_cipher);

    // Test decode
    vector<double> test_cipher_out;
    vector<double> test_plain_out;

    ckks_encoder.decode(test_cipher, test_cipher_out);
    cout << "First row cipher:" << endl;
    cout << "\t[";
    for (int i = 0; i < dimension1 - 1; i++)
    {
        cout << test_cipher_out[i] << ", ";
    }
    cout << test_cipher_out[dimension1 - 1];

    cout << "]" << endl;
}

void test_Linear_Transformation()
{
    int dimension1 = 8;
    // cout << "Dimension Set 1: " << dimension1 << endl
    //      << endl;

    vector<vector<double>> pod_matrix1_set1(dimension1, vector<double>(dimension1));
    vector<vector<double>> pod_matrix2_set1(dimension1, vector<double>(dimension1));

    // Fill input matrices
    double filler = 1.0;
    // Set 1
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            pod_matrix2_set1[i][j] = static_cast<double>((j % 2) + 1);
            filler++;
        }
    }
    // print_full_matrix(pod_matrix1_set1);
    // print_full_matrix(pod_matrix2_set1);

    vector<double> input_vec = pod_matrix1_set1[0];
    vector<double> result(dimension1);
    int k = 0;
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            result[k] += pod_matrix1_set1[i][j] * input_vec[j];
        }
        k++;
    }

    // Print Result vector
    cout << "Expected Result Vector: \n\t[";
    for (int i = 0; i < dimension1 - 1; i++)
    {
        cout << result[i] << ", ";
    }
    cout << result[dimension1 - 1] << "]" << endl;
}

int main()
{
    dotProd(4096);
    test_Linear_Transformation();

    return 0;
}