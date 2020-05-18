#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"
#include "helper.h"

using namespace std;
using namespace seal;

#define POLY_MOD_DEGREE 16384
#define DEGREE 3
#define ITERS 10
#define LEARNING_RATE 0.1

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
Ciphertext Tree_sigmoid_approx(Ciphertext ctx, int degree, double scale, vector<double> coeffs, CKKSEncoder &ckks_encoder, Evaluator &evaluator, Encryptor &encryptor, RelinKeys relin_keys, EncryptionParameters params)
{
    cout << "->" << __func__ << endl;

    auto context = SEALContext::Create(params);

    cout << "\nCTx Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(ctx.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(ctx.scale()) << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << ctx.scale() << endl;
    cout.copyfmt(old_fmt);
    cout << "\tSize:\t" << ctx.size() << endl;

    int depth = ceil(log2(degree));

    // vector<double> coeffs(degree + 1);
    vector<Plaintext> plain_coeffs(degree + 1);

    cout << "Polynomial = ";
    int counter = 0;
    for (size_t i = 0; i < degree + 1; i++)
    {
        // cout << "-> " << __LINE__ << endl;
        if (coeffs[i] == 0)
        {
            continue;
        }
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

    // cout << "-> " << __LINE__ << endl;

    compute_all_powers(ctx, degree, evaluator, relin_keys, powers);
    cout << "All powers computed " << endl;

    cout << "\nCTx Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(ctx.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(ctx.scale()) << endl;
    ios old_fmt1(nullptr);
    old_fmt1.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << ctx.scale() << endl;
    cout.copyfmt(old_fmt1);
    cout << "\tSize:\t" << ctx.size() << endl;

    Ciphertext enc_result;
    cout << "Encrypt first coeff...";
    encryptor.encrypt(plain_coeffs[0], enc_result);
    cout << "Done" << endl;

    cout << "\nenc_result Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(enc_result.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(enc_result.scale()) << endl;
    ios old_fmt2(nullptr);
    old_fmt2.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << enc_result.scale() << endl;
    cout.copyfmt(old_fmt2);
    cout << "\tSize:\t" << enc_result.size() << endl;

    Ciphertext temp;

    for (int i = 1; i <= degree; i++)
    {
        // cout << "-> " << __LINE__ << endl;

        evaluator.mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id());
        // cout << "-> " << __LINE__ << endl;

        evaluator.multiply_plain(powers[i], plain_coeffs[i], temp);
        // cout << "-> " << __LINE__ << endl;

        evaluator.rescale_to_next_inplace(temp);
        // cout << "-> " << __LINE__ << endl;

        evaluator.mod_switch_to_inplace(enc_result, temp.parms_id());
        // cout << "-> " << __LINE__ << endl;

        // Manual Rescale
        enc_result.scale() = pow(2.0, (int)log2(enc_result.scale()));
        temp.scale() = pow(2.0, (int)log2(enc_result.scale()));
        // cout << "-> " << __LINE__ << endl;

        evaluator.add_inplace(enc_result, temp);
    }
    // cout << "-> " << __LINE__ << endl;

    // // Compute Expected result
    // for (int i = degree - 1; i >= 0; i--)
    // {
    //     expected_result *= x;
    //     expected_result += coeffs[i];
    // }

    // decryptor.decrypt(enc_result, plain_result);
    // ckks_encoder.decode(plain_result, result);

    // cout << "Actual : " << result[0] << "\nExpected : " << expected_result << "\ndiff : " << abs(result[0] - expected_result) << endl;
    cout << "\nenc_result Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(enc_result.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(enc_result.scale()) << endl;
    ios old_fmt3(nullptr);
    old_fmt3.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << enc_result.scale() << endl;
    cout.copyfmt(old_fmt3);
    cout << "\tSize:\t" << enc_result.size() << endl;

    return enc_result;
}

Ciphertext Horner_sigmoid_approx(Ciphertext ctx, int degree, vector<double> coeffs, CKKSEncoder &ckks_encoder, double scale, Evaluator &evaluator, Encryptor &encryptor, RelinKeys relin_keys, EncryptionParameters params)
{
    auto context = SEALContext::Create(params);

    cout << "->" << __func__ << endl;
    cout << "->" << __LINE__ << endl;

    cout << "\nCTx Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(ctx.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(ctx.scale()) << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << ctx.scale() << endl;
    cout.copyfmt(old_fmt);
    cout << "\tSize:\t" << ctx.size() << endl;

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
    // cout << "->" << __LINE__ << endl;

    Ciphertext temp;
    encryptor.encrypt(plain_coeffs[degree], temp);

    Plaintext plain_result;
    vector<double> result;
    // cout << "->" << __LINE__ << endl;

    for (int i = degree - 1; i >= 0; i--)
    {
        // cout << "->" << __LINE__ << endl;
        // cout << "\nCTx Info:\n";
        // cout << "\tLevel:\t" << context->get_context_data(ctx.parms_id())->chain_index() << endl;
        // cout << "\tScale:\t" << log2(ctx.scale()) << endl;
        // ios old_fmt1(nullptr);
        // old_fmt1.copyfmt(cout);
        // cout << fixed << setprecision(10);
        // cout << "\tExact Scale:\t" << ctx.scale() << endl;
        // cout.copyfmt(old_fmt1);
        // cout << "\tSize:\t" << ctx.size() << endl;

        // cout << "\ntemp Info:\n";
        // cout << "\tLevel:\t" << context->get_context_data(temp.parms_id())->chain_index() << endl;
        // cout << "\tScale:\t" << log2(temp.scale()) << endl;
        // ios old_fmt2(nullptr);
        // old_fmt2.copyfmt(cout);
        // cout << fixed << setprecision(10);
        // cout << "\tExact Scale:\t" << temp.scale() << endl;
        // cout.copyfmt(old_fmt2);
        // cout << "\tSize:\t" << temp.size() << endl;

        int ctx_level = context->get_context_data(ctx.parms_id())->chain_index();
        int temp_level = context->get_context_data(temp.parms_id())->chain_index();
        if (ctx_level > temp_level)
        {
            evaluator.mod_switch_to_inplace(ctx, temp.parms_id());
        }
        else if (ctx_level < temp_level)
        {
            evaluator.mod_switch_to_inplace(temp, ctx.parms_id());
        }
        evaluator.multiply_inplace(temp, ctx);
        // cout << "->" << __LINE__ << endl;

        evaluator.relinearize_inplace(temp, relin_keys);

        evaluator.rescale_to_next_inplace(temp);
        // cout << "->" << __LINE__ << endl;

        evaluator.mod_switch_to_inplace(plain_coeffs[i], temp.parms_id());

        // Manual rescale
        temp.scale() = pow(2.0, 40);
        // cout << "->" << __LINE__ << endl;

        evaluator.add_plain_inplace(temp, plain_coeffs[i]);
    }
    // cout << "->" << __LINE__ << endl;

    cout << "\ntemp Info:\n";
    cout << "\tLevel:\t" << context->get_context_data(temp.parms_id())->chain_index() << endl;
    cout << "\tScale:\t" << log2(temp.scale()) << endl;
    ios old_fmt1(nullptr);
    old_fmt1.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact Scale:\t" << temp.scale() << endl;
    cout.copyfmt(old_fmt1);
    cout << "\tSize:\t" << temp.size() << endl;

    return temp;
}

// Predict Ciphertext Weights
Ciphertext predict_cipher_weights(vector<Ciphertext> features, Ciphertext weights, int num_weights, double scale, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor, EncryptionParameters params)
{
    cout << "->" << __func__ << endl;
    cout << "->" << __LINE__ << endl;

    // Linear Transformation (loop over rows and dot product)
    int num_rows = features.size();
    vector<Ciphertext> results(num_rows);

    for (int i = 0; i < num_rows; i++)
    {
        // Dot Product
        results[i] = cipher_dot_product(features[i], weights, num_weights, relin_keys, gal_keys, evaluator);
        // Create mask
        vector<double> mask_vec(num_rows, 0);
        mask_vec[i] = 1;
        Plaintext mask_pt;
        ckks_encoder.encode(mask_vec, scale, mask_pt);
        // Bring down mask by 1 level since dot product consumed 1 level
        evaluator.mod_switch_to_next_inplace(mask_pt);
        // Multiply result with mask
        evaluator.multiply_plain_inplace(results[i], mask_pt);
        // MAYBE RELIN, RESCALE AND MANUAL RESCALE AFTER LOOP ????? ---------------------
        // // Relin
        // evaluator.relinearize_inplace(results[i], relin_keys);
        // // Rescale
        // evaluator.rescale_to_next_inplace(results[i]);
        // // Manual Rescale
        // results[i].scale() = pow(2, (int)log2(results[i].scale()));
    }
    // Add all results to ciphertext vec
    Ciphertext lintransf_vec;
    evaluator.add_many(results, lintransf_vec);
    cout << "->" << __LINE__ << endl;
    // MAYBE RELIN, RESCALE AND MANUAL RESCALE AFTER LOOP ????? ---------------------
    // Relin
    evaluator.relinearize_inplace(lintransf_vec, relin_keys);
    // Rescale
    evaluator.rescale_to_next_inplace(lintransf_vec);
    // Manual Rescale
    lintransf_vec.scale() = pow(2, (int)log2(lintransf_vec.scale()));
    cout << "->" << __LINE__ << endl;
    // Sigmoid over result
    vector<double> coeffs;
    if (DEGREE == 3)
    {
        coeffs = {0.5, 1.20069, 0.00001, -0.81562};
    }
    else if (DEGREE == 5)
    {
        coeffs = {0.5, 1.53048, 0.00001, -2.3533056, 0.00001, 1.3511295};
    }
    else if (DEGREE == 7)
    {
        coeffs = {0.5, 1.73496, 0.00001, -4.19407, 0.00001, 5.43402, 0.00001, -2.50739};
    }
    else
    {
        cerr << "Invalid DEGREE" << endl;
        exit(EXIT_SUCCESS);
    }

    Ciphertext predict_res = Horner_sigmoid_approx(lintransf_vec, coeffs.size() - 1, coeffs, ckks_encoder, scale, evaluator, encryptor, relin_keys, params);
    cout << "->" << __LINE__ << endl;
    return predict_res;
}

Ciphertext update_weights(vector<Ciphertext> features, vector<Ciphertext> features_T, Ciphertext labels, Ciphertext weights, float learning_rate, Evaluator &evaluator, CKKSEncoder &ckks_encoder, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor, double scale, EncryptionParameters params)
{

    cout << "->" << __func__ << endl;
    cout << "->" << __LINE__ << endl;

    int num_observations = features.size();
    int num_weights = features_T.size();

    cout << "num obs = " << num_observations << endl;
    cout << "num weights = " << num_weights << endl;

    // cout << "->" << __func__ << endl;
    // cout << "->" << __LINE__ << endl;

    // Get predictions
    Ciphertext predictions = predict_cipher_weights(features, weights, num_weights, scale, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor, params);

    // cout << "->" << __LINE__ << endl;

    // Calculate Predictions - Labels
    // Mod switch labels
    evaluator.mod_switch_to_inplace(labels, predictions.parms_id());
    Ciphertext pred_labels;
    evaluator.sub(predictions, labels, pred_labels);

    // cout << "->" << __LINE__ << endl;

    // Calculate Gradient vector (loop over rows and dot product)

    vector<Ciphertext> gradient_results(num_weights);
    for (int i = 0; i < num_weights; i++)
    {
        // Mod switch features T [i]
        evaluator.mod_switch_to_inplace(features_T[i], pred_labels.parms_id());
        gradient_results[i] = cipher_dot_product(features_T[i], pred_labels, num_observations, relin_keys, gal_keys, evaluator);

        // Create mask
        vector<double> mask_vec(num_weights, 0);
        mask_vec[i] = 1;
        Plaintext mask_pt;
        ckks_encoder.encode(mask_vec, scale, mask_pt);
        // Multiply result with mask
        evaluator.multiply_plain_inplace(gradient_results[i], mask_pt);
        // MAYBE RELIN, RESCALE AND MANUAL RESCALE AFTER LOOP ????? ---------------------
        // // Relin
        // evaluator.relinearize_inplace(gradient_results[i], relin_keys);
        // // Rescale
        // evaluator.rescale_to_next_inplace(gradient_results[i]);
        // // Manual rescale
        // gradient_results[i].scale() = pow(2, (int)log2(gradient_results[i].scale()));
    }
    // Add all gradient results to gradient
    Ciphertext gradient;
    evaluator.add_many(gradient_results, gradient);
    // MAYBE RELIN, RESCALE AND MANUAL RESCALE AFTER LOOP ????? ---------------------
    // Relin
    evaluator.relinearize_inplace(gradient, relin_keys);
    // Rescale
    evaluator.rescale_to_next_inplace(gradient);
    // Manual rescale
    gradient.scale() = pow(2, (int)log2(gradient.scale()));

    // Multiply by learning_rate/observations
    double N = learning_rate / num_observations;

    cout << "LR / num_obs = " << N << endl;

    Plaintext N_pt;
    ckks_encoder.encode(N, N_pt);
    // Mod Switch N_pt
    evaluator.mod_switch_to_inplace(N_pt, gradient.parms_id());
    evaluator.multiply_plain_inplace(gradient, N_pt);
    // cout << "->" << __LINE__ << endl;

    // Subtract from weights
    Ciphertext new_weights;
    evaluator.sub(gradient, weights, new_weights);
    evaluator.negate_inplace(new_weights);
    // cout << "->" << __LINE__ << endl;

    return new_weights;
}

Ciphertext train_cipher(vector<Ciphertext> features, vector<Ciphertext> features_T, Ciphertext labels, Ciphertext weights, float learning_rate, int iters, int observations, int num_weights, Evaluator &evaluator, CKKSEncoder &ckks_encoder, double scale, GaloisKeys gal_keys, RelinKeys relin_keys, Encryptor &encryptor, Decryptor &decryptor, EncryptionParameters params)
{
    cout << "->" << __func__ << endl;
    cout << "->" << __LINE__ << endl;

    // Copy weights to new_weights
    Ciphertext new_weights = weights;

    for (int i = 0; i < iters; i++)
    {

        // Get new weights
        new_weights = update_weights(features, features_T, labels, new_weights, learning_rate, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor, scale, params);

        // Refresh weights
        Plaintext new_weights_pt;
        decryptor.decrypt(new_weights, new_weights_pt);
        vector<double> new_weights_decoded;
        ckks_encoder.decode(new_weights_pt, new_weights_decoded);

        // Log Progress
        if (i % 5 == 0)
        {
            cout << "\nIteration:\t" << i << endl;

            // Print weights
            cout << "Weights:\n\t[";
            for (int i = 0; i < num_weights; i++)
            {
                cout << new_weights_decoded[i] << ", ";
            }
            cout << "]" << endl;
        }

        encryptor.encrypt(new_weights_pt, new_weights);
    }

    return new_weights;
}

double sigmoid_approx_three(double x)
{
    cout << "->" << __func__ << endl;
    cout << "->" << __LINE__ << endl;

    double res;
    if (DEGREE == 3)
    {
        res = 0.5 + (1.20096 * (x / 8)) - (0.81562 * (pow((x / 8), 3)));
    }
    else if (DEGREE == 5)
    {
        res = 0.5 + (1.53048 * (x / 8)) - (2.3533056 * (pow((x / 8), 3))) + (1.3511295 * (pow((x / 8), 5)));
    }
    else if (DEGREE == 7)
    {
        res = 0.5 + (1.73496 * (x / 8)) - (4.19407 * (pow((x / 8), 3))) + (5.43402 * (pow((x / 8), 5))) - (2.50739 * (pow((x / 8), 3)));
    }
    else
    {
        cerr << "Invalid DEGREE" << endl;
        exit(EXIT_SUCCESS);
    }
    return res;
}

int main()
{

    // Test evaluate sigmoid approx
    EncryptionParameters params(scheme_type::CKKS);

    // int depth = ceil(log2(DEGREE));

    // vector<int> moduli(depth + 4, 40);
    // moduli[0] = 50;
    // moduli[moduli.size() - 1] = 59;

    // size_t poly_modulus_degree = 16384;
    params.set_poly_modulus_degree(POLY_MOD_DEGREE);
    params.set_coeff_modulus(CoeffModulus::Create(POLY_MOD_DEGREE, {60, 40, 40, 40, 40, 40, 40, 40, 60}));

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

    print_parameters(context);

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

    // Create coeffs (Change with degree)
    vector<double> coeffs;
    if (DEGREE == 3)
    {
        coeffs = {0.5, 1.20069, 0.00001, -0.81562};
    }
    else if (DEGREE == 5)
    {
        coeffs = {0.5, 1.53048, 0.00001, -2.3533056, 0.00001, 1.3511295};
    }
    else if (DEGREE == 7)
    {
        coeffs = {0.5, 1.73496, 0.00001, -4.19407, 0.00001, 5.43402, 0.00001, -2.50739};
    }
    else
    {
        cerr << "Invalid DEGREE" << endl;
        exit(EXIT_SUCCESS);
    }

    // Multiply x by 1/8
    double eight = 1 / 8;
    Plaintext eight_pt;
    ckks_encoder.encode(eight, scale, eight_pt);
    // evaluator.multiply_plain_inplace(ctx, eight_pt);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    // Ciphertext ct_res_sigmoid = Tree_sigmoid_approx(ctx, DEGREE, scale, coeffs, ckks_encoder, evaluator, encryptor, relin_keys, params);
    Ciphertext ct_res_sigmoid = Horner_sigmoid_approx(ctx, DEGREE, coeffs, ckks_encoder, scale, evaluator, encryptor, relin_keys, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Polynomial Evaluation Duration:\t" << time_diff.count() << " microseconds" << endl;

    // Decrypt and decode
    Plaintext pt_res_sigmoid;
    decryptor.decrypt(ct_res_sigmoid, pt_res_sigmoid);
    vector<double> res_sigmoid_vec;
    ckks_encoder.decode(pt_res_sigmoid, res_sigmoid_vec);

    // Get True expected result
    double true_expected_res = sigmoid(x_eight);

    // Get expected approximate result
    double expected_approx_res = sigmoid_approx_three(x);

    cout << "Actual Approximate Result =\t\t" << res_sigmoid_vec[0] << endl;
    cout << "Expected Approximate Result =\t\t" << expected_approx_res << endl;
    cout << "True Result =\t\t\t\t" << true_expected_res << endl;

    double difference = abs(res_sigmoid_vec[0] - true_expected_res);
    cout << "Approx. Error: Diff Actual and True =\t" << difference << endl;

    double horner_error = abs(res_sigmoid_vec[0] - expected_approx_res);
    cout << "CKKS Error: Diff Actual and Expected =\t" << horner_error << endl;

    // --------------------------- TEST LR -----------------------------------------
    cout << "\n--------------------------- TEST LR ---------------------------\n"
         << endl;

    // Read File
    string filename = "pulsar_stars_copy.csv";
    vector<vector<string>> s_matrix = CSVtoMatrix(filename);
    vector<vector<double>> f_matrix = stringToDoubleMatrix(s_matrix);

    // // Test print first 10 rows
    // cout << "First 10 rows of CSV file --------\n"
    //      << endl;
    // for (int i = 0; i < 10; i++)
    // {
    //     for (int j = 0; j < f_matrix[0].size(); j++)
    //     {
    //         cout << f_matrix[i][j] << ", ";
    //     }
    //     cout << endl;
    // }
    // cout << "...........\nLast 10 rows of CSV file ----------\n"
    //      << endl;
    // // Test print last 10 rows
    // for (int i = f_matrix.size() - 10; i < f_matrix.size(); i++)
    // {
    //     for (int j = 0; j < f_matrix[0].size(); j++)
    //     {
    //         cout << f_matrix[i][j] << ", ";
    //     }
    //     cout << endl;
    // }

    // Init features, labels and weights
    // Init features (rows of f_matrix , cols of f_matrix - 1)
    int rows = f_matrix.size();
    cout << "\nNumber of rows  = " << rows << endl;
    int cols = f_matrix[0].size() - 1;
    cout << "\nNumber of cols  = " << cols << endl;

    vector<vector<double>> features(rows, vector<double>(cols));
    // Init labels (rows of f_matrix)
    vector<double> labels(rows);
    // Init weight vector with zeros (cols of features)
    vector<double> weights(cols);

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
    }

    // Test print the features and labels
    cout << "\nTesting features\n--------------\n"
         << endl;

    // Features Print test
    cout << "Features row size = " << features.size() << endl;
    cout << "Features col size = " << features[0].size() << endl;

    cout << "Labels row size = " << labels.size() << endl;
    cout << "Weights row size = " << weights.size() << endl;

    // for (int i = 0; i < 10; i++)
    // {
    //     for (int j = 0; j < features[0].size(); j++)
    //     {
    //         cout << features[i][j] << ", ";
    //     }
    //     cout << endl;
    // }

    // Standardize the features
    cout << "\nSTANDARDIZE TEST---------\n"
         << endl;

    vector<vector<double>> standard_features = standard_scaler_double(features);

    // // Test print first 10 rows
    // for (int i = 0; i < 10; i++)
    // {
    //     for (int j = 0; j < cols; j++)
    //     {
    //         cout << standard_features[i][j] << ", ";
    //     }
    //     cout << endl;
    // }
    // cout << "..........." << endl;
    // // Test print last 10 rows
    // for (int i = rows - 10; i < rows; i++)
    // {
    //     for (int j = 0; j < cols; j++)
    //     {
    //         cout << standard_features[i][j] << ", ";
    //     }
    //     cout << endl;
    // }

    // cout << "\nTesting labels\n--------------\n"
    //      << endl;

    // // Labels Print Test
    // for (int i = 0; i < 10; i++)
    // {
    //     cout << labels[i] << ", ";
    // }
    // cout << endl;

    // Print old weights
    cout << "\nOLD WEIGHTS\n------------------"
         << endl;
    for (int i = 0; i < weights.size(); i++)
    {
        cout << weights[i] << ", ";
    }
    cout << endl;

    // Get tranpose from client
    vector<vector<double>> features_T = transpose_matrix(features);
    // Get diagonals of transposed matrix
    // vector<vector<double>> features_T_diagonals = get_all_diagonals(features_T);

    // -------------- ENCODING ----------------
    // Encode features diagonals
    // vector<vector<double>> features_diagonals = get_all_diagonals(features);
    vector<Plaintext> features_pt(features.size());
    cout << "\nENCODING FEATURES ...";
    for (int i = 0; i < features.size(); i++)
    {
        ckks_encoder.encode(features[i], scale, features_pt[i]);
    }
    cout << "Done" << endl;

    vector<Plaintext> features_T_pt(features_T.size());
    cout << "\nENCODING TRANSPOSED FEATURES ...";
    for (int i = 0; i < features_T.size(); i++)
    {
        ckks_encoder.encode(features_T[i], scale, features_T_pt[i]);
    }
    cout << "Done" << endl;

    // Encode weights
    Plaintext weights_pt;
    cout << "\nENCODING WEIGHTS...";
    ckks_encoder.encode(weights, scale, weights_pt);
    cout << "Done" << endl;

    // Encode labels
    Plaintext labels_pt;
    cout << "\nENCODING LABELS...";
    ckks_encoder.encode(labels, scale, labels_pt);
    cout << "Done" << endl;

    // -------------- ENCRYPTING ----------------
    //Encrypt features diagonals
    vector<Ciphertext> features_ct(features.size());
    cout << "\nENCRYPTING FEATURES ...";
    for (int i = 0; i < features.size(); i++)
    {
        encryptor.encrypt(features_pt[i], features_ct[i]);
    }
    cout << "Done" << endl;

    vector<Ciphertext> features_T_ct(features_T.size());
    cout << "\nENCRYPTING TRANSPOSED FEATURES ...";
    for (int i = 0; i < features_T.size(); i++)
    {
        encryptor.encrypt(features_T_pt[i], features_T_ct[i]);
    }
    cout << "Done" << endl;

    // Encrypt weights
    Ciphertext weights_ct;
    cout << "\nENCRYPTING WEIGHTS...";
    encryptor.encrypt(weights_pt, weights_ct);
    cout << "Done" << endl;

    // Encrypt labels
    Ciphertext labels_ct;
    cout << "\nENCRYPTING LABELS...";
    encryptor.encrypt(labels_pt, labels_ct);
    cout << "Done" << endl;

    // --------------- TRAIN ---------------
    cout << "\nTraining--------------\n"
         << endl;

    // Get U_tranpose
    // vector<vector<double>> U_transpose = get_U_transpose(features);

    int observations = features.size();
    int num_weights = features[0].size();

    Ciphertext predictions;
    // predictions = predict_cipher_weights(features_diagonals_ct, weights_ct, num_weights, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor);
    predictions = predict_cipher_weights(features_ct, weights_ct, num_weights, scale, evaluator, ckks_encoder, gal_keys, relin_keys, encryptor, params);

    return 0;
}