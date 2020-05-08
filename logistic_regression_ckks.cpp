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
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
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

    if (context_data.parms().scheme() == scheme_type::BFV)
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

Ciphertext Linear_Transform_Plain(Ciphertext ct, vector<Plaintext> U_diagonals, GaloisKeys gal_keys, Evaluator &evaluator)
{
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

void compute_all_powers(const Ciphertext &ctx, int degree, Evaluator &evaluator, RelinKeys &relin_keys, vector<Ciphertext> &powers)
{

    powers.resize(degree + 1);
    powers[1] = ctx;

    vector<int> levels(degree + 1, 0);
    levels[1] = 0;
    levels[0] = 0;
    cout << "-> " << __LINE__ << endl;

    for (int i = 2; i <= degree; i++)
    {
        // compute x^i
        int minlevel = i;
        int cand = -1;
        for (int j = 1; j <= i / 2; j++)
        {
            int k = i - j;
            //
            int newlevel = max(levels[j], levels[k]) + 1;
            if (newlevel < minlevel)
            {
                cand = j;
                minlevel = newlevel;
            }
        }
        cout << "-> " << __LINE__ << endl;

        levels[i] = minlevel;
        // use cand
        if (cand < 0)
            throw runtime_error("error");
        //cout << "levels " << i << " = " << levels[i] << endl;
        // cand <= i - cand by definition
        Ciphertext temp = powers[cand];
        evaluator.mod_switch_to_inplace(temp, powers[i - cand].parms_id());
        cout << "-> " << __LINE__ << endl;

        evaluator.multiply(temp, powers[i - cand], powers[i]);
        cout << "-> " << __LINE__ << endl;

        evaluator.relinearize_inplace(powers[i], relin_keys);
        cout << "-> " << __LINE__ << endl;

        evaluator.rescale_to_next_inplace(powers[i]);
    }
    cout << "-> " << __LINE__ << endl;

    return;
}

// Tree method for polynomial evaluation
void tree(int degree, double x)
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    EncryptionParameters parms(scheme_type::CKKS);

    int depth = ceil(log2(degree));

    vector<int> moduli(depth + 4, 40);
    moduli[0] = 50;
    moduli[moduli.size() - 1] = 59;

    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);

    KeyGenerator keygen(context);
    auto pk = keygen.public_key();
    auto sk = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);

    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    print_parameters(context);
    cout << endl;

    Plaintext ptx;
    ckks_encoder.encode(x, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);
    cout << "x = " << x << endl;

    vector<double> coeffs(degree + 1);
    vector<Plaintext> plain_coeffs(degree + 1);

    // Random Coefficients from 0-1
    cout << "Polynomial = ";
    int counter = 0;
    for (size_t i = 0; i < degree + 1; i++)
    {
        coeffs[i] = (double)rand() / RAND_MAX;
        ckks_encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << "x^" << counter << " * (" << coeffs[i] << ")"
             << ", ";
    }
    cout << endl;

    Plaintext plain_result;
    vector<double> result;

    /*
    decryptor.decrypt(ctx, plain_result);
    ckks_encoder.decode(plain_result, result);
    cout << "ctx  = " << result[0] << endl;
    */

    double expected_result = coeffs[degree];

    // Compute all powers
    vector<Ciphertext> powers(degree + 1);

    time_start = chrono::high_resolution_clock::now();

    compute_all_powers(ctx, degree, evaluator, relin_keys, powers);
    cout << "All powers computed " << endl;

    Ciphertext enc_result;
    // result = a[0]
    cout << "Encrypt first coeff...";
    encryptor.encrypt(plain_coeffs[0], enc_result);
    cout << "Done" << endl;

    /*
    for (int i = 1; i <= degree; i++){
        decryptor.decrypt(powers[i], plain_result);
        ckks_encoder.decode(plain_result, result);
        // cout << "power  = " << result[0] << endl;
    }
    */

    Ciphertext temp;

    // result += a[i]*x[i]
    for (int i = 1; i <= degree; i++)
    {

        // cout << i << "-th sum started" << endl;
        evaluator.mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id());
        evaluator.multiply_plain(powers[i], plain_coeffs[i], temp);

        evaluator.rescale_to_next_inplace(temp);
        evaluator.mod_switch_to_inplace(enc_result, temp.parms_id());

        // Manual Rescale
        enc_result.scale() = pow(2.0, 40);
        temp.scale() = pow(2.0, 40);

        evaluator.add_inplace(enc_result, temp);
        // cout << i << "-th sum done" << endl;
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Evaluation Duration:\t" << time_diff.count() << " microseconds" << endl;

    // Compute Expected result
    for (int i = degree - 1; i >= 0; i--)
    {
        expected_result *= x;
        expected_result += coeffs[i];
    }

    decryptor.decrypt(enc_result, plain_result);
    ckks_encoder.decode(plain_result, result);

    cout << "Actual : " << result[0] << "\nExpected : " << expected_result << "\ndiff : " << abs(result[0] - expected_result) << endl;

    // TEST Garbage
}

template <typename T>
vector<T> rotate_vec(vector<T> input_vec, int num_rotations)
{
    if (num_rotations > input_vec.size())
    {
        cerr << "Invalid number of rotations" << endl;
        exit(EXIT_FAILURE);
    }

    vector<T> rotated_res(input_vec.size());
    for (int i = 0; i < input_vec.size(); i++)
    {
        rotated_res[i] = input_vec[(i + num_rotations) % (input_vec.size())];
    }

    return rotated_res;
}

// Sigmoid
float sigmoid(float z)
{
    return 1 / (1 + exp(-z));
}

// Degree 3 Polynomial approximation of sigmoid function
Ciphertext Tree_sigmoid_approx(Ciphertext ctx, int degree, vector<double> coeffs, CKKSEncoder &ckks_encoder, Evaluator &evaluator, Encryptor &encryptor, RelinKeys relin_keys)
{
    // -------- write polynomial approximation --------

    int depth = ceil(log2(degree));

    vector<int> moduli(depth + 4, 40);
    moduli[0] = 50;
    moduli[moduli.size() - 1] = 59;

    double scale = pow(2.0, 40);

    // vector<double> coeffs(degree + 1);
    vector<Plaintext> plain_coeffs(degree + 1);

    cout << "Polynomial = ";
    int counter = 0;
    for (size_t i = 0; i < degree + 1; i++)
    {
        ckks_encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << "x^" << counter << " * (" << coeffs[i] << ")"
             << ", ";
        counter++;
    }
    cout << endl;

    Plaintext plain_result;
    vector<double> result;

    double expected_result = coeffs[degree];

    // Compute all powers
    vector<Ciphertext> powers(degree + 1);

    cout << "-> " << __LINE__ << endl;

    compute_all_powers(ctx, degree, evaluator, relin_keys, powers);
    cout << "All powers computed " << endl;

    Ciphertext enc_result;
    cout << "Encrypt first coeff...";
    encryptor.encrypt(plain_coeffs[0], enc_result);
    cout << "Done" << endl;

    Ciphertext temp;

    for (int i = 1; i <= degree; i++)
    {
        evaluator.mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id());
        evaluator.multiply_plain(powers[i], plain_coeffs[i], temp);

        evaluator.rescale_to_next_inplace(temp);
        evaluator.mod_switch_to_inplace(enc_result, temp.parms_id());

        // Manual Rescale
        enc_result.scale() = pow(2.0, 40);
        temp.scale() = pow(2.0, 40);

        evaluator.add_inplace(enc_result, temp);
    }

    // // Compute Expected result
    // for (int i = degree - 1; i >= 0; i--)
    // {
    //     expected_result *= x;
    //     expected_result += coeffs[i];
    // }

    // decryptor.decrypt(enc_result, plain_result);
    // ckks_encoder.decode(plain_result, result);

    // cout << "Actual : " << result[0] << "\nExpected : " << expected_result << "\ndiff : " << abs(result[0] - expected_result) << endl;

    return enc_result;
}

Ciphertext Horner_sigmoid_approx(Ciphertext ctx, int degree, vector<double> coeffs, CKKSEncoder &ckks_encoder, Evaluator &evaluator, Encryptor &encryptor, RelinKeys relin_keys)
{

    vector<int> moduli(degree + 4, 40);
    moduli[0] = 50;
    moduli[moduli.size() - 1] = 59;

    double scale = pow(2.0, 40);

    vector<Plaintext> plain_coeffs(degree + 1);

    // Random Coefficients from 0-1
    cout << "Polynomial = ";
    int counter = 0;
    for (size_t i = 0; i < degree + 1; i++)
    {
        // coeffs[i] = (double)rand() / RAND_MAX;
        ckks_encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << "x^" << counter << " * (" << coeffs[i] << ")"
             << ", ";
        counter++;
    }
    cout << endl;

    Ciphertext temp;
    encryptor.encrypt(plain_coeffs[degree], temp);

    Plaintext plain_result;
    vector<double> result;

    for (int i = degree - 1; i >= 0; i--)
    {

        evaluator.mod_switch_to_inplace(ctx, temp.parms_id());
        evaluator.multiply_inplace(temp, ctx);

        evaluator.relinearize_inplace(temp, relin_keys);

        evaluator.rescale_to_next_inplace(temp);

        evaluator.mod_switch_to_inplace(plain_coeffs[i], temp.parms_id());

        // Manual rescale
        temp.scale() = pow(2.0, 40);
        evaluator.add_plain_inplace(temp, plain_coeffs[i]);
    }

    return temp;
}

Ciphertext predict_plain_weights(vector<Ciphertext> features, Plaintext weights, int num_weights, double scale, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys)
{
    // Get rotations of weights
    vector<Plaintext> weights_rotations(num_weights);
    weights_rotations[0] = weights;

    vector<double> decoded_weights(num_weights);
    ckks_encoder.decode(weights, decoded_weights);

    for (int i = 1; i < num_weights; i++)
    {
        // rotate
        vector<double> rotated_vec = rotate_vec(decoded_weights, i);

        // encode
        Plaintext pt;
        ckks_encoder.encode(rotated_vec, scale, pt);

        // store
        weights_rotations[i] = pt;
    }

    // Linear Transformation
    Ciphertext lintransf_vec = Linear_Transform_CipherMatrix_PlainVector(weights_rotations, features, gal_keys, evaluator);

    // Sigmoid over result
    Ciphertext predict_res;

    return predict_res;
}

Ciphertext predict_cipher_weights(vector<Ciphertext> features_diagonals, Ciphertext weights, int num_weights, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor)
{

    // Linear Transformation
    Ciphertext lintransf_vec = Linear_Transform_Cipher(weights, features_diagonals, gal_keys, evaluator);

    // Sigmoid over result
    vector<double> coeffs = {0.5, 1.20069, 0, -0.81562};
    Ciphertext predict_res = Horner_sigmoid_approx(lintransf_vec, 3, coeffs, ckks_encoder, evaluator, encryptor, relin_keys);

    return predict_res;
}

Ciphertext update_weights(vector<Ciphertext> features_diagonals, Ciphertext labels, Ciphertext weights, float learning_rate, vector<Plaintext> U_transpose, int observations, int num_weights, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor, double scale)
{

    // Get predictions
    Ciphertext predictions;
    predictions = predict_cipher_weights(features_diagonals, weights, num_weights, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor);

    // Tranpose features matrix
    // Matrix Encode features diagonals
    Ciphertext features_diagonals_encoded = C_Matrix_Encode(features_diagonals, gal_keys, evaluator);
    // Transpose encoded features diagonals
    Ciphertext features_diagonals_T_encoded = Linear_Transform_Plain(features_diagonals_encoded, U_transpose, gal_keys, evaluator);
    //
    vector<Ciphertext> features_diagonals_T = C_Matrix_Decode(features_diagonals_T_encoded, num_weights, scale, gal_keys, ckks_encoder, evaluator);

    // Calculate Predictions - Labels
    Ciphertext pred_labels;
    evaluator.sub(predictions, labels, pred_labels);

    // Calculate Gradient vector
    Ciphertext gradient = Linear_Transform_Cipher(pred_labels, features_diagonals_T, gal_keys, evaluator);

    // Divide by N = 1/observations -> multiply by N_pt
    int N = 1 / observations;
    Plaintext N_pt;
    ckks_encoder.encode(N, N_pt);
    evaluator.multiply_plain_inplace(gradient, N_pt);

    // Multiply by learning rate
    Plaintext lr_pt;
    ckks_encoder.encode(learning_rate, lr_pt);
    evaluator.multiply_plain_inplace(gradient, lr_pt);

    // Subtract from weights
    Ciphertext new_weights;
    evaluator.sub(gradient, weights, new_weights);
    evaluator.negate_inplace(new_weights);

    return new_weights;
}

Ciphertext train(vector<Ciphertext> features_diagonals, Ciphertext labels, Ciphertext weights, float learning_rate, int iters, vector<Plaintext> U_transpose, int observations, int num_weights, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor, double scale)
{

    // Copy weights to new_weights
    Ciphertext new_weights = weights;

    for (int i = 0; i < iters; i++)
    {
        // Get new weights
        new_weights = update_weights(features_diagonals, labels, new_weights, learning_rate, U_transpose, observations, num_weights, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor, scale);

        // Get cost ????

        // Log Progress
        if (i % 100 == 0)
        {
            cout << "Iteration:\t" << i << endl;
        }
    }

    return new_weights;
}

double sigmoid_approx_three(double x)
{
    double res = 0.5 + (1.20096 * (x / 8)) - (0.81562 * (pow((x / 8), 3)));
    return res;
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
vector<vector<float>> stringToFloatMatrix(vector<vector<string>> matrix)
{
    vector<vector<float>> result(matrix.size(), vector<float>(matrix[0].size()));
    for (int i = 0; i < matrix.size(); i++)
    {
        for (int j = 0; j < matrix[0].size(); j++)
        {
            result[i][j] = ::atof(matrix[i][j].c_str());
        }
    }

    return result;
}

// Mean calculation
float getMean(vector<float> input_vec)
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
float getStandardDev(vector<float> input_vec, float mean)
{
    float variance = 0;
    for (int i = 0; i < input_vec.size(); i++)
    {
        variance += pow(input_vec[i] - mean, 2);
    }
    variance /= input_vec.size();

    float standard_dev = sqrt(variance);
    return standard_dev;
}

// Standard Scaler
vector<vector<float>> standard_scaler(vector<vector<float>> input_matrix)
{
    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();
    vector<vector<float>> result_matrix(rowSize, vector<float>(colSize));

    // Optimization: Get Means and Standard Devs first then do the scaling
    // first pass: get means and standard devs
    vector<float> means_vec(colSize);
    vector<float> stdev_vec(colSize);
    for (int i = 0; i < colSize; i++)
    {
        vector<float> column(rowSize);
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

float RandomFloat(float a, float b)
{
    float random = ((float)rand()) / (float)RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

int main()
{

    // Test evaluate sigmoid approx
    EncryptionParameters params(scheme_type::CKKS);

    int degree = 3;

    int depth = ceil(log2(degree));

    vector<int> moduli(depth + 4, 40);
    moduli[0] = 50;
    moduli[moduli.size() - 1] = 59;

    size_t poly_modulus_degree = 16384;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, moduli));

    double scale = pow(2.0, 40);

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

    // -------------------------- TEST SIGMOID APPROXIMATION ---------------------------
    cout << "\n------------------- TEST SIGMOID APPROXIMATION -------------------\n"
         << endl;

    // Create data
    double x = 0.8;
    double x_eight = x / 8;
    Plaintext ptx;
    ckks_encoder.encode(x_eight, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);

    // Create coeffs
    vector<double> coeffs = {0.5, 1.20069, 0, -0.81562};

    // Multiply x by 1/8
    double eight = 1 / 8;
    Plaintext eight_pt;
    ckks_encoder.encode(eight, scale, eight_pt);
    // evaluator.multiply_plain_inplace(ctx, eight_pt);

    // Ciphertext ct_res_sigmoid = Tree_sigmoid_approx(ctx, degree, coeffs, ckks_encoder, evaluator, encryptor, relin_keys);
    Ciphertext ct_res_sigmoid = Horner_sigmoid_approx(ctx, degree, coeffs, ckks_encoder, evaluator, encryptor, relin_keys);

    // Decrypt and decode
    Plaintext pt_res_sigmoid;
    decryptor.decrypt(ct_res_sigmoid, pt_res_sigmoid);
    vector<double> res_sigmoid_vec;
    ckks_encoder.decode(pt_res_sigmoid, res_sigmoid_vec);

    // Get True expected result
    double true_expected_res = sigmoid(x_eight);

    // Get expected approximate result
    double expected_approx_res = sigmoid_approx_three(x);

    cout << "Actual Approximate Result =\t" << res_sigmoid_vec[0] << endl;
    cout << "Expected Approximate Result =\t" << expected_approx_res << endl;
    cout << "True Result =\t\t\t" << expected_approx_res << endl;

    double difference = abs(res_sigmoid_vec[0] - true_expected_res);
    cout << "Diff Actual and True =\t\t" << difference << endl;

    double horner_error = abs(res_sigmoid_vec[0] - expected_approx_res);
    cout << "Diff Actual and Expected =\t" << horner_error << endl;

    // --------------------------- TEST LR -----------------------------------------
    cout << "\n--------------------------- TEST LR ---------------------------\n"
         << endl;

    // Read File
    string filename = "pulsar_stars.csv";
    vector<vector<string>> s_matrix = CSVtoMatrix(filename);
    vector<vector<float>> f_matrix = stringToFloatMatrix(s_matrix);

    // Test print first 10 rows
    cout << "First 10 rows of CSV file --------\n"
         << endl;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ", ";
        }
        cout << endl;
    }
    cout << "...........\nLast 10 rows of CSV file ----------\n"
         << endl;
    // Test print last 10 rows
    for (int i = f_matrix.size() - 10; i < f_matrix.size(); i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ", ";
        }
        cout << endl;
    }

    // Init features, labels and weights
    // Init features (rows of f_matrix , cols of f_matrix - 1)
    int rows = f_matrix.size();
    cout << "\nNumber of rows  = " << rows << endl;
    int cols = f_matrix[0].size() - 1;
    cout << "\nNumber of cols  = " << cols << endl;

    vector<vector<float>> features(rows, vector<float>(cols));
    // Init labels (rows of f_matrix)
    vector<float> labels(rows);
    // Init weight vector with zeros (cols of features)
    vector<float> weights(cols);

    // Fill the features matrix and labels vector
    for (int i = 0; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            features[i][j] = f_matrix[i][j];
        }
        labels[i] = f_matrix[i][cols];
    }

    // Fill the weights with random numbers (from 1 - 2)
    for (int i = 0; i < cols; i++)
    {
        weights[i] = RandomFloat(-2, 2);
        cout << "weights[i] = " << weights[i] << endl;
    }

    // Test print the features and labels
    cout << "\nTesting features\n--------------\n"
         << endl;

    // Features Print test
    cout << "Features row size = " << features.size() << endl;
    cout << "Features col size = " << features[0].size() << endl;

    cout << "Labels row size = " << labels.size() << endl;
    cout << "Weights row size = " << weights.size() << endl;

    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < features[0].size(); j++)
        {
            cout << features[i][j] << ", ";
        }
        cout << endl;
    }

    // Standardize the features
    cout << "\nSTANDARDIZE TEST---------\n"
         << endl;

    vector<vector<float>> standard_features = standard_scaler(features);

    // Test print first 10 rows
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            cout << standard_features[i][j] << ", ";
        }
        cout << endl;
    }
    cout << "..........." << endl;
    // Test print last 10 rows
    for (int i = rows - 10; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            cout << standard_features[i][j] << ", ";
        }
        cout << endl;
    }

    cout << "\nTesting labels\n--------------\n"
         << endl;

    // Labels Print Test
    for (int i = 0; i < 10; i++)
    {
        cout << labels[i] << ", ";
    }
    cout << endl;

/*
    // TRAIN
    cout << "\nTraining--------------\n"
         << endl;
    tuple<vector<float>, vector<float>> training_tuple = train(standard_features, labels, weights, 0.1, 100);

    vector<float> new_weights = get<0>(training_tuple);
    vector<float> cost_history = get<1>(training_tuple);

    // Print old weights
    cout << "\nOLD WEIGHTS\n------------------"
         << endl;
    for (int i = 0; i < weights.size(); i++)
    {
        cout << weights[i] << ", ";
    }
    cout << endl;

    // Print mew weights
    cout << "\nNEW WEIGHTS\n------------------"
         << endl;
    for (int i = 0; i < new_weights.size(); i++)
    {
        cout << new_weights[i] << ", ";
    }
    cout << endl;

    // Print Cost history
    cout << "\nCOST HISTORY\n------------------"
         << endl;
    for (int i = 0; i < cost_history.size(); i++)
    {
        cout << cost_history[i] << ", ";
        if (i % 10 == 0 && i > 0)
        {
            cout << "\n";
        }
    }
    cout << endl;

    // Print Accuracy
    cout << "\nACCURACY\n-------------------" << endl;
*/
    return 0;
}