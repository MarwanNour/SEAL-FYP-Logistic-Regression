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

Ciphertext Linear_Transform(Ciphertext ct, vector<Plaintext> U_plain, vector<Plaintext> U_diagonals, EncryptionParameters params, GaloisKeys gal_keys)
{
    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    Ciphertext ct_result;
    // ct` = CMult(ct, u0)
    evaluator.multiply_plain(ct, U_diagonals[0], ct_result);

    for (int l = 1; l < U_plain.size(); l++)
    {
        // ct` = Add(ct`, CMult(Rot(ct, l), ul))
        Ciphertext temp_rot;
        Ciphertext temp_mul;
        evaluator.rotate_vector(ct, l, gal_keys, temp_rot);
        evaluator.multiply_plain(temp_rot, U_diagonals[l], temp_mul);
        evaluator.add_inplace(ct_result, temp_mul);
    }

    return ct_result;
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
    double scale = params.coeff_modulus().back().value() / 2;

    int dimension1 = 4;
    cout << "Dimension Set 1: " << dimension1 << endl
         << endl;

    vector<vector<double>> pod_matrix1_set1(dimension1, vector<double>(dimension1));
    vector<vector<double>> pod_matrix2_set1(dimension1, vector<double>(dimension1));

    // Fill input matrices
    double filler = 0.0;
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
    //Ciphertext ct_prime = Linear_Transform(cipher_matrix1_set1[0], plain_matrix1_set1, plain_diagonal1_set1, params, gal_keys);

    Ciphertext ct_prime;
    // ct` = CMult(ct, u0)
    evaluator.multiply_plain(cipher_matrix1_set1[0], plain_diagonal2_set1[0], ct_prime);

    for (int l = 1; l < dimension1; l++)
    {
        // ct` = Add(ct`, CMult(Rot(ct, l), ul))
        Ciphertext temp_rot;
        Ciphertext temp_mul;
        evaluator.rotate_vector(cipher_matrix1_set1[0], l, gal_keys, temp_rot);
        evaluator.multiply_plain(temp_rot, plain_diagonal2_set1[l], temp_mul);
        evaluator.add_inplace(ct_prime, temp_mul);
    }

    // Decrypt
    Plaintext pt_result;
    decryptor.decrypt(ct_prime, pt_result);

    // Decode
    vector<double> output_result;
    ckks_encoder.decode(pt_result, output_result);

    cout << "Linear Transformation Result (cipher_matrix1_set1[0], plain_matrix2_set1, plain_diagonal2_set1):" << endl;
    cout << "\t[";
    for (int i = 0; i < dimension1 - 1; i++)
    {
        cout << output_result[i] << ", ";
    }
    cout << output_result[dimension1 - 1];

    cout << "]" << endl;
}

int main()
{
    dotProd(4096);

    return 0;
}