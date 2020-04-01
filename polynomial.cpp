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
    cout << "|   poly_modulus_degree: " <<
        context_data.parms().poly_modulus_degree() << endl;

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
        cout << "|   plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\" << endl;
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
        cout << "x^" << counter <<  " * (" << coeffs[i] << ")" << ", ";
        counter ++;
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
    cout << "Evaluation Done in \t" << time_diff.count() << " microseconds" << endl;


    decryptor.decrypt(temp, plain_result);
    ckks_encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;
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
            cout << "Tree method not yet available" << endl;
            break;

        case 0:
            cout << "Exit" << endl;
            return 0;
        }
    }

    return 0;
}