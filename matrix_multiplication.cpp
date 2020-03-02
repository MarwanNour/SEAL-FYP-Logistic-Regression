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

template <typename T>
void print_full_vector(vector<T> vec)
{
    cout << "\t[ ";
    for (unsigned int i = 0; i < vec.size() - 1; i++)
    {
        cout << vec[i] << ", ";
    }
    cout << vec[vec.size() - 1] << " ]" << endl;
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

template <typename T>
vector<vector<T>> get_all_diagonals(vector<vector<T>> U)
{

    vector<vector<T>> diagonal_matrix(U.size());

    for (int i = 0; i < U.size(); i++)
    {
        diagonal_matrix[i] = get_diagonal(i, U);
    }

    return diagonal_matrix;
}

template <typename T>
vector<vector<double>> get_matrix_of_ones(int position, vector<vector<T>> U)
{
    vector<vector<double>> diagonal_of_ones(U.size(), vector<double>(U.size()));
    vector<T> U_diag = get_diagonal(position, U);

    int k = 0;
    for (int i = 0; i < U.size(); i++)
    {
        for (int j = 0; j < U.size(); j++)
        {
            if (U[i][j] == U_diag[k])
            {
                diagonal_of_ones[i][j] = 1;
            }
            else
            {
                diagonal_of_ones[i][j] = 0;
            }
        }
        k++;
    }

    return diagonal_of_ones;
}

// Encodes Ciphertext Matrix into a single vector (Row ordering of a matix)
Ciphertext C_Matrix_Encode(vector<Ciphertext> matrix, GaloisKeys gal_keys, EncryptionParameters params)
{
    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    Ciphertext ct_result;
    int dimension = matrix.size();
    vector<Ciphertext> ct_rots(dimension);
    ct_rots[0] = matrix[0];

    for (int i = 1; i < dimension; i++)
    {
        evaluator.rotate_vector(matrix[i], (i * -dimension), gal_keys, ct_rots[i]);
    }

    evaluator.add_many(ct_rots, ct_result);

    return ct_result;
}

template <typename T>
vector<double> pad_zero(int offset, vector<T> U_vec)
{

    vector<double> result_vec(pow(U_vec.size(), 2));
    // Fill before U_vec
    for (int i = 0; i < offset; i++)
    {
        result_vec[i] = 0;
    }
    // Fill U_vec
    for (int i = 0; i < U_vec.size(); i++)
    {
        result_vec[i + offset] = U_vec[i];
    }
    // Fill after U_vec
    for (int i = offset + U_vec.size(); i < result_vec.size(); i++)
    {
        result_vec[i] = 0;
    }
    return result_vec;
}

// U_sigma
template <typename T>
vector<vector<double>> get_U_sigma(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_sigma(dimensionSq, vector<double>(dimensionSq));

    int k = 0;
    int sigma_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        // Get the matrix of ones at position k
        vector<vector<double>> one_matrix = get_matrix_of_ones(k, U);
        // print_full_matrix(one_matrix);
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            // Store vector in U_sigma at position index_sigma
            // print_full_vector(temp_fill);
            U_sigma[sigma_row] = temp_fill;
            sigma_row++;
        }

        k++;
    }

    return U_sigma;
}

// U_sigma
template <typename T>
vector<vector<double>> get_U_tau(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_tau(dimensionSq, vector<double>(dimensionSq));

    int tau_row = 0;
    // Divide the matrix into blocks of size = dimension
    for (int i = 0; i < dimension; i++)
    {
        // Get the matrix of ones at position i
        vector<vector<double>> one_matrix = get_matrix_of_ones(i, U);
        // print_full_matrix(one_matrix);

        int offset = 0;
        // Loop over the matrix of ones and store in U_tau the rows of the matrix of ones with the offset
        for (int j = 0; j < dimension; j++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[j]);
            // print_full_vector(temp_fill);

            offset += dimension;
            U_tau[tau_row] = temp_fill;
            tau_row++;
        }
    }

    return U_tau;
}

// V_k
template <typename T>
vector<vector<double>> get_V_k(vector<vector<T>> U, int k)
{

    int dimension = U.size();
    if (k < 1 || k >= dimension)
    {
        cerr << "Invalid K for matrix V_k: " << to_string(k) << ". Choose k to be between 1 and " << to_string(dimension) << endl;
        exit(1);
    }

    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> V_k(dimensionSq, vector<double>(dimensionSq));

    int V_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        // Get the matrix of ones at position k
        vector<vector<double>> one_matrix = get_matrix_of_ones(k, U);
        // print_full_matrix(one_matrix);
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            // Store vector in V_k at position V_row
            // print_full_vector(temp_fill);
            V_k[V_row] = temp_fill;
            V_row++;
        }
    }

    return V_k;
}

// W_k
template <typename T>
vector<vector<double>> get_W_k(vector<vector<T>> U, int k)
{

    int dimension = U.size();
    if (k < 1 || k >= dimension)
    {
        cerr << "Invalid K for matrix V_k: " << to_string(k) << ". Choose k to be between 1 and " << to_string(dimension) << endl;
        exit(1);
    }

    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> W_k(dimensionSq, vector<double>(dimensionSq));

    int W_row = 0;
    // Get matrix of ones at position 0
    vector<vector<double>> one_matrix = get_matrix_of_ones(0, U);
    int offset = k * dimension;

    // Divide the W matrix into several blocks of size dxd and store matrix of ones in them with offsets
    for (int i = 0; i < dimension; i++)
    {
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<double> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
            // Store vector in W_k at position W_row
            // print_full_vector(temp_fill);
            W_k[W_row] = temp_fill;
            W_row++;
        }
        if (offset + dimension == dimensionSq)
        {
            offset = 0;
        }
        else
        {
            offset += dimension;
        }
    }

    return W_k;
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

Ciphertext CC_Matrix_Multiplication(Ciphertext ctA, Ciphertext ctB, int dimension, vector<Plaintext> U_sigma_diagonals, vector<Plaintext> U_tau_diagonals, vector<vector<Plaintext>> V_diagonals, vector<vector<Plaintext>> W_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{

    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);

    // Step 1-1
    ctA_result[0] = Linear_Transform_Plain(ctA, U_sigma_diagonals, gal_keys, params);

    // Step 1-2
    ctB_result[0] = Linear_Transform_Plain(ctB, U_sigma_diagonals, gal_keys, params);

    // Step 2
    for (int k = 1; k < dimension; k++)
    {
        ctA_result[k] = Linear_Transform_Plain(ctA_result[0], V_diagonals[k], gal_keys, params);
        ctB_result[k] = Linear_Transform_Plain(ctB_result[0], W_diagonals[k], gal_keys, params);
    }

    // Step 3
    Ciphertext ctAB;
    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);

    for (int k = 1; k < dimension; k++)
    {
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }

    return ctAB;
}

void Matrix_Multiplication(size_t poly_modulus_degree, int dimension)
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

    // Create Scale
    double scale = pow(2.0, 40);

    vector<vector<double>> pod_matrix1_set1(dimension, vector<double>(dimension));
    vector<vector<double>> pod_matrix2_set1(dimension, vector<double>(dimension));

    // Fill input matrices
    // double r = ((double)rand() / (RAND_MAX));
    double filler = 0;
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
    print_partial_matrix(pod_matrix1_set1);

    filler = 0;
    // Matrix 2
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix2_set1[i][j] = filler;
            // r = ((double)rand() / (RAND_MAX));
            filler++;
        }
    }

    cout << "Matrix 2:" << endl;
    print_partial_matrix(pod_matrix2_set1);

    int dimensionSq = pow(dimension, 2);

    // Get U_sigma for first matrix
    vector<vector<double>> U_sigma = get_U_sigma(pod_matrix1_set1);
    cout << "\nU_sigma:" << endl;
    print_full_matrix(U_sigma, 0);

    // Get U_tau for second matrix
    vector<vector<double>> U_tau = get_U_sigma(pod_matrix1_set1);
    cout << "\nU_tau:" << endl;
    print_full_matrix(U_tau, 0);

    // Get V_k (3D matrix)
    vector<vector<vector<double>>> V_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k[i - 1] = get_V_k(pod_matrix1_set1, i);
        cout << "\nV_" << to_string(i) << ":" << endl;
        print_full_matrix(V_k[i - 1], 0);
    }

    // Get W_k (3D matrix)
    vector<vector<vector<double>>> W_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k[i - 1] = get_W_k(pod_matrix1_set1, i);
        cout << "\nW_" << to_string(i) << ":" << endl;
        print_full_matrix(W_k[i - 1], 0);
    }

    // Get Diagonals for U_sigma
    vector<vector<double>> U_sigma_diagonals = get_all_diagonals(U_sigma);

    // Get Diagonals for U_tau
    vector<vector<double>> U_tau_diagonals = get_all_diagonals(U_tau);

    // Get Diagonals for V_k
    vector<vector<vector<double>>> V_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k_diagonals[i - 1] = get_all_diagonals(V_k[i - 1]);
    }

    // Get Diagonals for W_k
    vector<vector<vector<double>>> W_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k_diagonals[i - 1] = get_all_diagonals(W_k[i - 1]);
    }

    // --------------- ENCODING ----------------
    // Encode U_sigma diagonals
    vector<Plaintext> U_sigma_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_sigma_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_sigma_diagonals[i], scale, U_sigma_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode U_tau diagonals
    vector<Plaintext> U_tau_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_tau_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_tau_diagonals[i], scale, U_tau_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode V_k diagonals
    vector<vector<Plaintext>> V_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding V_K_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(V_k_diagonals[i - 1][j], scale, V_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode W_k
    vector<vector<Plaintext>> W_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding W_k_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(W_k_diagonals[i - 1][j], scale, W_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode Matrices
    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    cout << "\nEncoding Matrix 1...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // Encode Matrix 2
    vector<Plaintext> plain_matrix2_set1(dimension);
    cout << "\nEncoding Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix2_set1[i], scale, plain_matrix2_set1[i]);
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

    // Encrypt Matrix 2
    vector<Ciphertext> cipher_matrix2_set1(dimension);
    cout << "\nEncrypting Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    cout << "\nMatrix Encoding Matrix 1...";
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, params);
    cout << "Done" << endl;

    // Matrix Encode Matrix 2
    cout << "\nMatrix Encoding Matrix 2...";
    Ciphertext cipher_encoded_matrix2_set1 = C_Matrix_Encode(cipher_matrix2_set1, gal_keys, params);
    cout << "Done" << endl;

    // Test Matrix Encoding
    Plaintext test_matrix_encoding;
    decryptor.decrypt(cipher_encoded_matrix1_set1, test_matrix_encoding);
    vector<double> test_matrix_encoding_result(dimensionSq);
    ckks_encoder.decode(test_matrix_encoding, test_matrix_encoding_result);

    cout << "[";
    for (int i = 0; i < dimensionSq - 1; i++)
    {
        cout << test_matrix_encoding_result[i] << ", ";
    }
    cout << test_matrix_encoding_result[dimensionSq - 1] << "]" << endl;

    // Test Matrix Multiplication
    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);
    // Step 1-1
    ctA_result[0] = Linear_Transform_Plain(cipher_encoded_matrix1_set1, U_sigma_diagonals_plain, gal_keys, params);

    // Step 1-2
    ctB_result[0] = Linear_Transform_Plain(cipher_encoded_matrix2_set1, U_sigma_diagonals_plain, gal_keys, params);
    /*
    // Step 2
    for (int k = 1; k < dimension; k++)
    {
        ctA_result[k] = Linear_Transform_Plain(ctA_result[0], V_diagonals[k], gal_keys, params);
        ctB_result[k] = Linear_Transform_Plain(ctB_result[0], W_diagonals[k], gal_keys, params);
    }

    // Step 3
    Ciphertext ctAB;
    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);

    for (int k = 1; k < dimension; k++)
    {
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }
    */
    /*

    // --------------- MATRIX MULTIPLICATION ----------------
    cout << "\nMatrix Multiplication...";
    cout << "test " << endl;
    Ciphertext ct_result = CC_Matrix_Multiplication(cipher_encoded_matrix1_set1, cipher_encoded_matrix2_set1, dimension, U_sigma_diagonals_plain, U_tau_diagonals_plain, V_k_diagonals_plain, W_k_diagonals_plain, gal_keys, params);
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

    print_full_vector(result_matrix);
    */
}

int main()
{

    /*
    int dimension1 = 4;
    vector<vector<double>> pod_matrix1_set1(dimension1, vector<double>(dimension1));

    // Fill input matrices
    double filler = 0.0;
    // Set 1
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            filler++;
        }
    }
    cout << "\nInput Matrix:" << endl;
    print_full_matrix(pod_matrix1_set1);

    // vector<vector<int>> U_0 = get_matrix_of_ones(2, pod_matrix1_set1);

    // print_full_matrix(U_0);

    vector<vector<int>> U_sigma = get_U_sigma(pod_matrix1_set1);
    // print_partial_matrix(U_sigma);
    cout << "\nU_sigma:" << endl;
    print_full_matrix(U_sigma);

    vector<vector<int>> U_tau = get_U_tau(pod_matrix1_set1);
    cout << "\nU_tau:" << endl;
    print_full_matrix(U_tau);

    vector<vector<int>> V_1 = get_V_k(pod_matrix1_set1, 1);
    cout << "\nV_1:" << endl;
    print_full_matrix(V_1);

    vector<vector<int>> W_1 = get_W_k(pod_matrix1_set1, 1);
    cout << "\nW_1:" << endl;
    print_full_matrix(W_1);
*/

    Matrix_Multiplication(8192, 5);

    return 0;
}
