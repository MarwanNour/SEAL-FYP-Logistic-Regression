#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
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
            //
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
        //cout << "levels " << i << " = " << levels[i] << endl;
        // cand <= i - cand by definition
        Ciphertext temp = powers[cand];
        evaluator.mod_switch_to_inplace(temp, powers[i - cand].parms_id());

        evaluator.multiply(temp, powers[i - cand], powers[i]);
        evaluator.relinearize_inplace(powers[i], relin_keys);
        evaluator.rescale_to_next_inplace(powers[i]);
    }
    return;
}

// Horner's method for polynomial evaluation
void horner(int degree, double x)
{

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    vector<int> moduli(degree + 4, 40);
    moduli[0] = 50;
    moduli[moduli.size() - 1] = 59;

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
        counter++;
    }
    cout << endl;

    time_start = chrono::high_resolution_clock::now();

    Ciphertext temp;
    cout << "Encrypt last coeff...";
    encryptor.encrypt(plain_coeffs[degree], temp);
    cout << "Done" << endl;

    Plaintext plain_result;
    vector<double> result;
    /*
    decryptor.decrypt(ctx, plain_result);
    ckks_encoder.decode(plain_result, result);
    cout << "ctx  = " << result[0] << endl;
    */

    double expected_result = coeffs[degree];

    for (int i = degree - 1; i >= 0; i--)
    {

        // temp *= x
        expected_result *= x;
        evaluator.mod_switch_to_inplace(ctx, temp.parms_id());
        evaluator.multiply_inplace(temp, ctx);

        /*
        decryptor.decrypt(temp, plain_result);
        ckks_encoder.decode(plain_result, result);
        cout << "temp2 = " << result[0] << endl;
        */

        evaluator.relinearize_inplace(temp, relin_keys);

        /*
        decryptor.decrypt(temp, plain_result);
        ckks_encoder.decode(plain_result, result);
        cout << "temp after relin = " << result[0] << endl;
        */

        evaluator.rescale_to_next_inplace(temp);

        /*
        decryptor.decrypt(temp, plain_result);
        ckks_encoder.decode(plain_result, result);
        cout << "temp1  = " << result[0] << endl;
        */

        // temp += a[i]
        expected_result += coeffs[i];

        evaluator.mod_switch_to_inplace(plain_coeffs[i], temp.parms_id());

        // Manual rescale
        temp.scale() = pow(2.0, 40);
        evaluator.add_plain_inplace(temp, plain_coeffs[i]);

        //cout << i << "-th iteration done" << endl;

        /*
        decryptor.decrypt(temp, plain_result);
        ckks_encoder.decode(plain_result, result);
        cout << "temp = " << result[0] << endl;
        */
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Evaluation Duration:\t" << time_diff.count() << " microseconds" << endl;

    decryptor.decrypt(temp, plain_result);
    ckks_encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

    cout << "Actual : " << result[0] << "\nExpected : " << expected_result << "\ndiff : " << abs(result[0] - expected_result) << endl;
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
}

int main()
{

    int degree = 0;
    cout << "Enter Degree: ";
    cin >> degree;

    double x = 0;
    cout << "Enter x value: ";
    cin >> x;
    cout << endl;

    if (degree > 15)
    {
        cerr << "Invalid degree" << endl;
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        cout << "\nSelect method:\n"
             << endl;
        cout << "   1. Horner" << endl;
        cout << "   2. Tree" << endl;
        cout << "   0. Quit" << endl;

        int selection = 0;

        if (!(cin >> selection))
        {
            cout << "Invalid option" << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        switch (selection)
        {
        case 1:
            horner(degree, x);
            break;

        case 2:
            tree(degree, x);
            break;

        case 0:
            cout << "Exit" << endl;
            return 0;
        }
    }

    return 0;
}