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

    cout << "pos = " << position << endl;

    int numCols = U[0].size();
    int numRows = U.size();

    vector<T> diagonal(numCols);

    if (numRows == numCols) // WORKS
    {
        cout << "numRows == numCols" << endl;
        int k = 0;
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
    }
    else if (numRows < numCols) // WORKS
    {
        cout << "numRows < numCols" << endl;
        int k = 0;
        int i = 0;
        int j;
        for (int j = position; j < numCols; j++)
        {
            if (i == numRows)
            {
                i = 0;
            }
            diagonal[k] = U[i][j];
            k++;
            i++;
        }
        for (i = U.size() - position, j = 0; (i < U.size()) && (j < position); i++, j++)
        {
            diagonal[k] = U[i][j];
            k++;
        }
    }
    else // DOESN'T WORK !!!!
    {

        cout << "numRows > numCols" << endl;
        /*
        int k = 0;
        for (int i = 0, j = position; (i < U.size() - position) && (j < U.size()); i++, j++)
        {
            diagonal[k] = U[i][j];
            cout << diagonal[k] << ", ";
            k++;
        }
        for (int i = U.size() - position, j = 0; (i < U.size()) && (j < position); i++, j++)
        {
            diagonal[k] = U[i][j];
            cout << diagonal[k] << ", ";
            k++;
        }
        */
    }
    return diagonal;
}

template <typename T>
vector<vector<T>> get_all_diagonals(vector<vector<T>> U)
{

    int numRows = U.size();
    int numCols = U[0].size();

    vector<vector<T>> diagonal_matrix(numRows, vector<T>(numCols));

    for (int i = 0; i < numRows; i++)
    {
        diagonal_matrix[i] = get_diagonal(i, U);
    }

    return diagonal_matrix;
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
Ciphertext C_Matrix_Encode(vector<Ciphertext> matrix, GaloisKeys gal_keys, Evaluator &evaluator)
{
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

// Decodes Ciphertext Matrix into vector of Ciphertexts
vector<Ciphertext> C_Matrix_Decode(Ciphertext matrix, int dimension, double scale, GaloisKeys gal_keys, CKKSEncoder &ckks_encoder, Evaluator &evaluator)
{

    vector<Ciphertext> ct_result(dimension);
    for (int i = 0; i < dimension; i++)
    {
        // Create masks vector with 1s and 0s
        // Fill mask vector with 0s
        vector<double> mask_vec(pow(dimension, 2), 0);

        // Store 1s in mask vector at dimension offset. Offset = j + (i * dimension)
        for (int j = 0; j < dimension; j++)
        {
            mask_vec[j + (i * dimension)] = 1;
        }

        // Encode mask vector
        Plaintext mask_pt;
        ckks_encoder.encode(mask_vec, scale, mask_pt);

        // multiply matrix with mask
        Ciphertext ct_row;
        evaluator.multiply_plain(matrix, mask_pt, ct_row);

        // rotate row (not the first one)
        if (i != 0)
        {
            evaluator.rotate_vector_inplace(ct_row, i * dimension, gal_keys);
        }

        // store in result
        ct_result[i] = ct_row;
    }

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

// U_transpose
template <typename T>
vector<vector<double>> get_U_transpose(vector<vector<T>> U)
{

    int dimension = U.size();
    int dimensionSq = pow(dimension, 2);
    vector<vector<double>> U_transpose(dimensionSq, vector<double>(dimensionSq));

    int tranposed_row = 0;

    for (int i = 0; i < dimension; i++)
    {
        // Get matrix of ones at position k
        vector<vector<double>> one_matrix = get_matrix_of_ones(i, U);
        print_full_matrix(one_matrix);

        // Loop over matrix of ones
        for (int offset = 0; offset < dimension; offset++)
        {
            vector<double> temp_fill = pad_zero(offset * dimension, one_matrix[0]);

            U_transpose[tranposed_row] = temp_fill;
            tranposed_row++;
        }
    }

    return U_transpose;
}

// Matrix Transpose
template <typename T>
vector<vector<T>> transpose_matrix(vector<vector<T>> input_matrix)
{

    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();
    vector<vector<T>> transposed(colSize, vector<T>(rowSize));

    for (int i = 0; i < rowSize; i++)
    {
        for (int j = 0; j < colSize; j++)
        {
            transposed[j][i] = input_matrix[i][j];
        }
    }

    return transposed;
}

// Ciphertext dot product
Ciphertext cipher_dot_product(Ciphertext ctA, Ciphertext ctB, int size, RelinKeys relin_keys, GaloisKeys gal_keys, Evaluator &evaluator)
{

    // cout << "\nCTA Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(ctA.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(ctA.scale()) << endl;
    // ios old_fmt(nullptr);
    // old_fmt.copyfmt(cout);
    // cout << fixed << setprecision(10);
    // cout << "\tExact Scale:\t" << ctA.scale() << endl;
    // cout.copyfmt(old_fmt);
    // cout << "\tSize:\t" << ctA.size() << endl;

    Ciphertext mult;

    // Component-wise multiplication
    evaluator.multiply(ctA, ctB, mult);

    // cout << "\nMult Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(mult.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(mult.scale()) << endl;
    // cout << "\tExact Scale:\t" << mult.scale() << endl;
    // cout << "\tSize:\t" << mult.size() << endl;

    evaluator.relinearize_inplace(mult, relin_keys);
    evaluator.rescale_to_next_inplace(mult);

    // cout << "\nMult Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(mult.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(mult.scale()) << endl;
    // ios old_fmt1(nullptr);
    // old_fmt1.copyfmt(cout);
    // cout << fixed << setprecision(10);
    // cout << "\tExact Scale:\t" << mult.scale() << endl;
    // cout.copyfmt(old_fmt1);
    // cout << "\tSize:\t" << mult.size() << endl;

    // Fill with duplicate
    Ciphertext zero_filled;
    evaluator.rotate_vector(mult, -size, gal_keys, zero_filled); // vector has zeros now

    // cout << "\nZero Filled Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(zero_filled.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(zero_filled.scale()) << endl;
    // cout << "\tExact Scale:\t" << zero_filled.scale() << endl;
    // cout << "\tSize:\t" << zero_filled.size() << endl;

    Ciphertext dup;
    evaluator.add(mult, zero_filled, dup); // vector has duplicate now

    // cout << "\nDup Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(dup.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(dup.scale()) << endl;
    // cout << "\tExact Scale:\t" << dup.scale() << endl;
    // cout << "\tSize:\t" << dup.size() << endl;

    for (int i = 1; i < size; i++)
    {
        evaluator.rotate_vector_inplace(dup, 1, gal_keys);
        evaluator.add_inplace(mult, dup);
    }

    // cout << "\nMult Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(mult.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(mult.scale()) << endl;
    // ios old_fmt2(nullptr);
    // old_fmt2.copyfmt(cout);
    // cout << fixed << setprecision(10);
    // cout << "\tExact Scale:\t" << mult.scale() << endl;
    // cout.copyfmt(old_fmt2);
    // cout << "\tSize:\t" << mult.size() << endl;

    // Manual Rescale
    mult.scale() = pow(2, (int)log2(mult.scale()));

    // cout << "\nMult Info:\n";
    // cout << "\tLevel:\t" << context->get_context_data(mult.parms_id())->chain_index() << endl;
    // cout << "\tScale:\t" << log2(mult.scale()) << endl;
    // ios old_fmt3(nullptr);
    // old_fmt3.copyfmt(cout);
    // cout << fixed << setprecision(10);
    // cout << "\tExact Scale:\t" << mult.scale() << endl;
    // cout.copyfmt(old_fmt3);
    // cout << "\tSize:\t" << mult.size() << endl;

    return mult;
}

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