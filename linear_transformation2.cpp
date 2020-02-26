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

template <typename T>
inline void print_partial_vector(vector<T> vec, int size, int print_size = 3, int precision = 3)
{
    // save formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);

    int row_size = size;

    // Boundary check
    if (row_size < 2 * print_size)
    {
        cerr << "Cannot print vector with these dimensions: " << to_string(row_size) << ". Increase the print size" << endl;
        return;
    }

    cout << "\t[";
    for (unsigned int row = 0; row < print_size; row++)
    {
        cout << vec[row] << ", ";
    }
    cout << "..., ";

    for (unsigned int row = row_size - print_size; row < row_size - 1; row++)
    {
        cout << vec[row] << ", ";
    }
    cout << vec[row_size - 1] << "]\n";

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

Ciphertext Linear_Transform_Plain(Ciphertext ct, vector<Plaintext> U_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{
    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    // Fill ct with duplicate
    Ciphertext ct_rot;
    evaluator.rotate_vector(ct, -U_diagonals.size(), gal_keys, ct_rot);
    // cout << "U_diagonals.size() = " << U_diagonals.size() << endl;
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

Ciphertext Linear_Transform_Cipher(Ciphertext ct, vector<Ciphertext> U_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{
    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    // Fill ct with duplicate
    Ciphertext ct_rot;
    evaluator.rotate_vector(ct, -U_diagonals.size(), gal_keys, ct_rot);
    // cout << "U_diagonals.size() = " << U_diagonals.size() << endl;
    Ciphertext ct_new;
    evaluator.add(ct, ct_rot, ct_new);

    vector<Ciphertext> ct_result(U_diagonals.size());
    evaluator.multiply(ct_new, U_diagonals[0], ct_result[0]);

    for (int l = 1; l < U_diagonals.size(); l++)
    {
        Ciphertext temp_rot;
        evaluator.rotate_vector(ct_new, l, gal_keys, temp_rot);
        evaluator.multiply(temp_rot, U_diagonals[l], ct_result[l]);
    }
    Ciphertext ct_prime;
    evaluator.add_many(ct_result, ct_prime);

    return ct_prime;
}

void test_Linear_Transformation(int dimension, vector<vector<double>> input_matrix, vector<double> input_vec)
{
    vector<double> result(dimension);
    int k = 0;
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            result[k] += input_matrix[i][j] * input_vec[j];
        }
        k++;
    }

    // Print Result vector
    print_partial_vector(result, dimension);
}

void PMatrix_CVector_Multiplication(size_t poly_modulus_degree, int dimension)
{
    EncryptionParameters params(scheme_type::CKKS);
    params.set_poly_modulus_degree(poly_modulus_degree);
    cout << "MAX BIT COUNT: " << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
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
    double scale = pow(2.0, 40);

    // Set output file
    string filename = "linear_transf_p" + to_string(poly_modulus_degree) + "_d" + to_string(dimension) + ".dat";
    ofstream outf(filename);

    // Handle file error
    if (!outf)
    {
        cerr << "Couldn't open file: " << filename << endl;
        exit(1);
    }

    // Set output script
    string script = "script_linear_transf_p" + to_string(poly_modulus_degree) + "_d" + to_string(dimension) + ".p";
    ofstream outscript(script);

    // Handle script error
    if (!outscript)
    {
        cerr << "Couldn't open file: " << script << endl;
        exit(1);
    }

    // Write to Script
    outscript << "# Set the output terminal" << endl;
    outscript << "set terminal canvas" << endl;
    outscript << "set output \"canvas_linear_transf_p" << to_string(poly_modulus_degree) << "_d" << to_string(dimension) << ".html\"" << endl;
    outscript << "set title \"Linear Transformation Benchmark " << to_string(poly_modulus_degree) << "\"" << endl;
    outscript << "set xlabel 'Dimension'" << endl;
    outscript << "set ylabel 'Time (microseconds)'" << endl;
    outscript << "set logscale" << endl;
    outscript << "set ytics nomirror" << endl;
    outscript << "set xtics nomirror" << endl;
    outscript << "set grid" << endl;
    outscript << "set key outside" << endl;

    outscript << "\n# Set the styling " << endl;
    outscript << "set style line 1\\\n"
              << "linecolor rgb '#0060ad'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 7 pointsize 1.5\n"
              << endl;

    outscript << "set style line 2\\\n"
              << "linecolor rgb '#dd181f'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 5 pointsize 1.5\n"
              << endl;

    outscript << "\nplot 'linear_transf_p" << to_string(poly_modulus_degree) << "_d" << to_string(dimension)
              << ".dat' index 0 title \"C_Vec * P_Mat\" with linespoints ls 1, \\\n"
              << "'' index 1 title \"C_Vec * C_Mat\"  with linespoints ls 2";
    // Close script
    outscript.close();

    cout << "Dimension : " << dimension << endl
         << endl;

    vector<vector<double>> pod_matrix_set1(dimension, vector<double>(dimension));
    vector<double> pod_vec_set1(dimension);

    // Fill input matrices

    double r = ((double)rand() / (RAND_MAX));

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix_set1[i][j] = r;
            r = ((double)rand() / (RAND_MAX));
        }
    }

    for (int i = 0; i < dimension; i++)
    {
        r = ((double)rand() / (RAND_MAX));
        pod_vec_set1[i] = r;
    }

    cout << "Matrix:" << endl;
    print_partial_matrix(pod_matrix_set1);
    cout << "Vector:" << endl;
    print_partial_vector(pod_vec_set1, dimension);

    // Get all diagonals
    vector<vector<double>> all_diagonal_set1(dimension, vector<double>(dimension));

    for (int i = 0; i < dimension; i++)
    {
        all_diagonal_set1[i] = get_diagonal(i, pod_matrix_set1);
    }

    cout << "Diagonal Expected:" << endl;
    print_partial_matrix(all_diagonal_set1);

    // Encode Matrices into vectors with Diagonals
    vector<Plaintext> plain_matrix_set1(dimension);
    Plaintext plain_vec_set1;
    vector<Plaintext> plain_diagonal_set1(dimension);

    auto start_encode = chrono::high_resolution_clock::now();
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix_set1[i], scale, plain_matrix_set1[i]);
        ckks_encoder.encode(pod_vec_set1, scale, plain_vec_set1);
        ckks_encoder.encode(all_diagonal_set1[i], scale, plain_diagonal_set1[i]);
    }
    auto stop_encode = chrono::high_resolution_clock::now();

    cout << "Encoding is Complete" << endl;
    auto duration_encode = chrono::duration_cast<chrono::microseconds>(stop_encode - start_encode);
    cout << "Encode Duration:\t" << duration_encode.count() << endl;

    // Encrypt the matrices with Diagonals
    vector<Ciphertext> cipher_matrix_set1(dimension);
    Ciphertext cipher_vec_set1;
    vector<Ciphertext> cipher_diagonal_set1(dimension);

    auto start_encrypt = chrono::high_resolution_clock::now();
    for (unsigned int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix_set1[i], cipher_matrix_set1[i]);
        encryptor.encrypt(plain_vec_set1, cipher_vec_set1);
        encryptor.encrypt(plain_diagonal_set1[i], cipher_diagonal_set1[i]);
    }
    auto stop_encrypt = chrono::high_resolution_clock::now();

    cout << "Encrypting is Complete" << endl;
    auto duration_encrypt = chrono::duration_cast<chrono::microseconds>(stop_encrypt - start_encrypt);
    cout << "Encrypt Duration:\t" << duration_encrypt.count() << endl;

    // ------------- FIRST COMPUTATION ----------------
    outf << "# index 0" << endl;
    outf << "# C_Vec . P_Mat" << endl;

    // Test LinearTransform here
    auto start_comp1_set1 = chrono::high_resolution_clock::now();
    Ciphertext ct_prime1_set1 = Linear_Transform_Plain(cipher_matrix_set1[0], plain_diagonal_set1, gal_keys, params);
    auto stop_comp1_set1 = chrono::high_resolution_clock::now();

    auto duration_comp1_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set1 - start_comp1_set1);
    cout << "\nTime to compute C_vec . P_mat: " << duration_comp1_set1.count() << " microseconds" << endl;
    outf << to_string(dimension) << "\t\t" << duration_comp1_set1.count() << endl;

    // Decrypt
    Plaintext pt_result1_set1;
    auto start_decrypt = chrono::high_resolution_clock::now();
    decryptor.decrypt(ct_prime1_set1, pt_result1_set1);
    auto stop_decrypt = chrono::high_resolution_clock::now();
    auto duration_decrypt = chrono::duration_cast<chrono::microseconds>(stop_decrypt - start_decrypt);
    cout << "Decrypt Duration:\t" << duration_decrypt.count() << endl;
    
    // Decode
    vector<double> output_result1_set1;
    auto start_decode = chrono::high_resolution_clock::now();
    ckks_encoder.decode(pt_result1_set1, output_result1_set1);
    auto stop_decode = chrono::high_resolution_clock::now();
    auto duration_decode = chrono::duration_cast<chrono::microseconds>(stop_decode - start_decode);
    cout << "Decode Duration:\t" << duration_decode.count() << endl;

    cout << "Linear Transformation:" << endl;
    print_partial_vector(output_result1_set1, dimension);

    // Check result
    cout << "Expected output: " << endl;

    test_Linear_Transformation(dimension, pod_matrix_set1, pod_matrix_set1[0]);

    outf << "\n"
         << endl;
    outf.close();
}

int main()
{
    PMatrix_CVector_Multiplication(8192, 100);

    return 0;
}