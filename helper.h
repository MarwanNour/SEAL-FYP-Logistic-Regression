#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper function that prints parameters
void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->key_context_data();

    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }
    cout << "/" << endl;
    cout << "| Encryption parameters :" << endl;
    cout << "|   scheme: " << scheme_name << endl;
    cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;

    cout << "|   coeff_modulus size: ";
    cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    size_t coeff_mod_count = coeff_modulus.size();
    for (size_t i = 0; i < coeff_mod_count - 1; i++)
    {
        cout << coeff_modulus[i].bit_count() << " + ";
    }
    cout << coeff_modulus.back().bit_count();
    cout << ") bits" << endl;

    if (context_data.parms().scheme() == scheme_type::bfv)
    {
        cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << endl;
    }

    cout << "\\" << endl;
}

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

// Helper function that prints parts of a vector
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

// Gets all diagonals from a matrix U into a matrix
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

// Linear Transformation function between ciphertext matrix and ciphertext vector
Ciphertext Linear_Transform_Cipher(Ciphertext ct, vector<Ciphertext> U_diagonals, GaloisKeys gal_keys, Evaluator &evaluator)
{
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

// Linear Transformation function between plaintext  matrix and ciphertext vector
Ciphertext Linear_Transform_Plain(Ciphertext ct, vector<Plaintext> U_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{
    SEALContext context(params);
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

// Linear transformation function between ciphertext matrix and plaintext vector
Ciphertext Linear_Transform_CipherMatrix_PlainVector(vector<Plaintext> pt_rotations, vector<Ciphertext> U_diagonals, GaloisKeys gal_keys, Evaluator &evaluator)
{
    vector<Ciphertext> ct_result(pt_rotations.size());

    for (int i = 0; i < pt_rotations.size(); i++)
    {
        evaluator.multiply_plain(U_diagonals[i], pt_rotations[i], ct_result[i]);
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

// Helper for Tree method, computes powers of x in a tree
void compute_all_powers(const Ciphertext &ctx, int degree, Evaluator &evaluator, RelinKeys &relin_keys, vector<Ciphertext> &powers)
{

    powers.resize(degree + 1);
    powers[1] = ctx;

    vector<int> levels(degree + 1, 0);
    levels[1] = 0;
    levels[0] = 0;

    for (int i = 2; i <= degree; i++)
    {
        // compute x^i
        int minlevel = i;
        int cand = -1;
        for (int j = 1; j <= i / 2; j++)
        {
            int k = i - j;
            int newlevel = max(levels[j], levels[k]) + 1;
            if (newlevel < minlevel)
            {
                cand = j;
                minlevel = newlevel;
            }
        }

        levels[i] = minlevel;
        // use cand
        if (cand < 0)
            throw runtime_error("error");
        // cand <= i - cand by definition
        Ciphertext temp = powers[cand];
        evaluator.mod_switch_to_inplace(temp, powers[i - cand].parms_id());

        evaluator.multiply(temp, powers[i - cand], powers[i]);

        evaluator.relinearize_inplace(powers[i], relin_keys);

        evaluator.rescale_to_next_inplace(powers[i]);
    }

    return;
}

// Gets a random float between a and b
float RandomFloat(float a, float b)
{
    float random = ((float)rand()) / (float)RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

// CSV to string matrix converter
vector<vector<string>> CSVtoMatrix(string filename)
{
    vector<vector<string>> result_matrix;

    ifstream data(filename);
    string line;
    int line_count = 0;
    while (getline(data, line))
    {
        stringstream lineStream(line);
        string cell;
        vector<string> parsedRow;
        while (getline(lineStream, cell, ','))
        {
            parsedRow.push_back(cell);
        }
        // Skip first line since it has text instead of numbers
        if (line_count != 0)
        {
            result_matrix.push_back(parsedRow);
        }
        line_count++;
    }
    return result_matrix;
}

// String matrix to float matrix converter
vector<vector<double>> stringToDoubleMatrix(vector<vector<string>> matrix)
{
    vector<vector<double>> result(matrix.size(), vector<double>(matrix[0].size()));
    for (int i = 0; i < matrix.size(); i++)
    {
        for (int j = 0; j < matrix[0].size(); j++)
        {
            result[i][j] = ::atof(matrix[i][j].c_str());
            result[i][j] = static_cast<double>(result[i][j]);
        }
    }

    return result;
}

// Mean calculation
double getMean(vector<double> input_vec)
{
    float mean = 0;
    for (int i = 0; i < input_vec.size(); i++)
    {
        mean += input_vec[i];
    }
    mean /= input_vec.size();

    return mean;
}

// Standard Dev calculation
double getStandardDev(vector<double> input_vec, double mean)
{
    double variance = 0;
    for (int i = 0; i < input_vec.size(); i++)
    {
        variance += pow(input_vec[i] - mean, 2);
    }
    variance /= input_vec.size();

    double standard_dev = sqrt(variance);
    return standard_dev;
}

// Standard Scaler
vector<vector<double>> standard_scaler_double(vector<vector<double>> input_matrix)
{
    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();
    vector<vector<double>> result_matrix(rowSize, vector<double>(colSize));

    // Optimization: Get Means and Standard Devs first then do the scaling
    // first pass: get means and standard devs
    vector<double> means_vec(colSize);
    vector<double> stdev_vec(colSize);
    for (int i = 0; i < colSize; i++)
    {
        vector<double> column(rowSize);
        for (int j = 0; j < rowSize; j++)
        {
            // cout << input_matrix[j][i] << ", ";
            column[j] = input_matrix[j][i];
            // cout << column[j] << ", ";
        }

        means_vec[i] = getMean(column);
        stdev_vec[i] = getStandardDev(column, means_vec[i]);
        // cout << "MEAN at i = " << i << ":\t" << means_vec[i] << endl;
        // cout << "STDV at i = " << i << ":\t" << stdev_vec[i] << endl;
    }

    // second pass: scale
    for (int i = 0; i < rowSize; i++)
    {
        for (int j = 0; j < colSize; j++)
        {
            result_matrix[i][j] = (input_matrix[i][j] - means_vec[j]) / stdev_vec[j];
            // cout << "RESULT at i = " << i << ":\t" << result_matrix[i][j] << endl;
        }
    }

    return result_matrix;
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

// Print entire vector
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
        vector<vector<double>> one_matrix = get_matrix_of_ones(0, U);
        // print_full_matrix(one_matrix);
        // Loop over the matrix of ones and store in U_tau the rows of the matrix of ones with the offset
        int offset = i * dimension;

        for (int j = 0; j < dimension; j++)
        {
            vector<double> temp_fill = pad_zero(offset, one_matrix[j]);
            // print_full_vector(temp_fill);
            U_tau[tau_row] = temp_fill;
            tau_row++;
            // Update offset
            if (offset + dimension == dimensionSq)
            {
                offset = 0;
            }
            else
            {
                offset += dimension;
            }
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
