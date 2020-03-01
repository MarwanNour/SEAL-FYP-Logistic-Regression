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
vector<vector<int>> get_matrix_of_ones(int position, vector<vector<T>> U)
{
    vector<vector<int>> diagonal_of_ones(U.size(), vector<int>(U.size()));
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

// Encodes Ciphertext Matrix into a single vector (Row ordering of a matix)
Ciphertext Matrix_Encode(vector<Ciphertext> matrix, GaloisKeys gal_keys, EncryptionParameters params)
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
vector<int> pad_zero(int offset, vector<T> U_vec)
{

    vector<int> result_vec(pow(U_vec.size(), 2));
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
vector<vector<int>> get_U_sigma(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<int>> U_sigma(dimensionSq, vector<int>(dimensionSq));

    int k = 0;
    int sigma_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        // Get the matrix of ones at position k
        vector<vector<int>> one_matrix = get_matrix_of_ones(k, U);
        // print_full_matrix(one_matrix);
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<int> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
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
vector<vector<int>> get_U_theta(vector<vector<T>> U)
{
    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<int>> U_theta(dimensionSq, vector<int>(dimensionSq));

    int theta_row = 0;
    // Divide the matrix into blocks of size = dimension
    for (int i = 0; i < dimension; i++)
    {
        // Get the matrix of ones at position i
        vector<vector<int>> one_matrix = get_matrix_of_ones(i, U);
        // print_full_matrix(one_matrix);

        int offset = 0;
        // Loop over the matrix of ones and store in U_theta the rows of the matrix of ones with the offset
        for (int j = 0; j < dimension; j++)
        {
            vector<int> temp_fill = pad_zero(offset, one_matrix[j]);
            // print_full_vector(temp_fill);

            offset += dimension;
            U_theta[theta_row] = temp_fill;
            theta_row++;
        }
    }

    return U_theta;
}

// V_k
template <typename T>
vector<vector<int>> get_V_k(vector<vector<T>> U, int k)
{

    int dimension = U.size();
    if (k < 1 || k >= dimension)
    {
        cerr << "Invalid K for matrix V_k: " << to_string(k) << ". Choose k to be between 1 and " << to_string(dimension) << endl;
        exit(1);
    }

    int dimensionSq = pow(dimension, 2);
    vector<vector<int>> V_k(dimensionSq, vector<int>(dimensionSq));

    int V_row = 0;
    for (int offset = 0; offset < dimensionSq; offset += dimension)
    {
        // Get the matrix of ones at position k
        vector<vector<int>> one_matrix = get_matrix_of_ones(k, U);
        // print_full_matrix(one_matrix);
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<int> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
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
vector<vector<int>> get_W_k(vector<vector<T>> U, int k)
{

    int dimension = U.size();
    if (k < 1 || k >= dimension)
    {
        cerr << "Invalid K for matrix V_k: " << to_string(k) << ". Choose k to be between 1 and " << to_string(dimension) << endl;
        exit(1);
    }

    int dimensionSq = pow(dimension, 2);
    vector<vector<int>> W_k(dimensionSq, vector<int>(dimensionSq));

    int W_row = 0;
    // Get matrix of ones at position 0
    vector<vector<int>> one_matrix = get_matrix_of_ones(0, U);
    int offset = k * dimension;

    // Divide the W matrix into several blocks of size dxd and store matrix of ones in them with offsets
    for (int i = 0; i < dimension; i++)
    {
        // Loop over the matrix of ones
        for (int one_matrix_index = 0; one_matrix_index < dimension; one_matrix_index++)
        {
            // Pad with zeros the vector of one
            vector<int> temp_fill = pad_zero(offset, one_matrix[one_matrix_index]);
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
    double r = ((double)rand() / (RAND_MAX));

    // Matrix 1
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix1_set1[i][j] = r;
            r = ((double)rand() / (RAND_MAX));
        }
    }

    cout << "Matrix 1:" << endl;
    print_partial_matrix(pod_matrix1_set1);

    // Matrix 2
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix2_set1[i][j] = r;
            r = ((double)rand() / (RAND_MAX));
        }
    }

    cout << "Matrix 2:" << endl;
    print_partial_matrix(pod_matrix2_set1);

    int dimensionSq = pow(dimension, 2);

    // Get U_sigma for first matrix
    vector<vector<int>> U_sigma = get_U_sigma(pod_matrix1_set1);

    // Get U_theta for second matrix
    vector<vector<int>> U_theta = get_U_sigma(pod_matrix1_set1);

    // Get V_k (3D matrix)
    vector<vector<vector<int>>> V_k(dimension - 1, vector<vector<int>>(dimensionSq, vector<int>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k[i - 1] = get_V_k(pod_matrix1_set1, i);
    }

    // Get W_k (3D matrix)
    vector<vector<vector<int>>> W_k(dimension - 1, vector<vector<int>>(dimensionSq, vector<int>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k[i - 1] = get_W_k(pod_matrix1_set1, i);
    }

    // Get Diagonals for U_sigma
    vector<vector<int>> U_sigma_diagonals(dimensionSq, vector<int>(dimensionSq));

    for (int i = 0; i < dimensionSq; i++)
    {
        U_sigma_diagonals[i] = get_diagonal(i, U_sigma);
    }

    // Get Diagonals for U_theta
    vector<vector<int>> U_theta_diagonals(dimensionSq, vector<int>(dimensionSq));

    for (int i = 0; i < dimensionSq; i++)
    {
        U_theta_diagonals[i] = get_diagonal(i, U_theta);
    }

    // Get Diagonals for V_k
    // Get Diagonals for W_k
}

int main()
{

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

    vector<vector<int>> U_theta = get_U_theta(pod_matrix1_set1);
    cout << "\nU_theta:" << endl;
    print_full_matrix(U_theta);

    vector<vector<int>> V_1 = get_V_k(pod_matrix1_set1, 1);
    cout << "\nV_1:" << endl;
    print_full_matrix(V_1);

    vector<vector<int>> W_1 = get_W_k(pod_matrix1_set1, 1);
    cout << "\nW_1:" << endl;
    print_full_matrix(W_1);

    return 0;
}