#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void example_polyeval_horner(int degree)
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
    // print_parameters(context);
    cout << endl;

    cout << "Generating keys...";
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    cout << "...done " << endl;

    // generate random input.
    double x = 1.1;
    Plaintext ptx;
    encoder.encode(x, scale, ptx);
    Ciphertext ctx;
    encryptor.encrypt(ptx, ctx);
    cout << "x = " << x << endl;

    vector<double> coeffs(degree + 1);
    vector<Plaintext> plain_coeffs(degree + 1);

    cout << "Poly = ";
    for (size_t i = 0; i < degree + 1; i++)
    {
        coeffs[i] = (double)rand() / RAND_MAX;
        encoder.encode(coeffs[i], scale, plain_coeffs[i]);
        cout << coeffs[i] << ", ";
    }
    cout << endl;

    time_start = chrono::high_resolution_clock::now();

    Ciphertext temp;
    encryptor.encrypt(plain_coeffs[degree], temp);

    cout << "encryption done " << endl;

    Plaintext plain_result;
    vector<double> result;
    //decryptor.decrypt(ctx, plain_result);
    //encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

    double expected_result = coeffs[degree];

    for (int i = degree - 1; i >= 0; i--)
    {

        // temp*= x
        expected_result *= x;
        evaluator.mod_switch_to_inplace(ctx, temp.parms_id());
        evaluator.multiply_inplace(temp, ctx);

        /*
        decryptor.decrypt(temp, plain_result);
        encoder.decode(plain_result, result);
        cout << "temp2 = " << result[0] << endl;
        */

        evaluator.relinearize_inplace(temp, relin_keys);

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp after relin = " << result[0] << endl;

        evaluator.rescale_to_next_inplace(temp);

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp1  = " << result[0] << endl;

        // temp += a[i]
        expected_result += coeffs[i];

        evaluator.mod_switch_to_inplace(plain_coeffs[i], temp.parms_id());

        temp.scale() = pow(2.0, 40); // manually reset the scale
        evaluator.add_plain_inplace(temp, plain_coeffs[i]);

        //cout << i << "-th iteration done" << endl;

        //decryptor.decrypt(temp, plain_result);
        //encoder.decode(plain_result, result);
        //cout << "temp = " << result[0] << endl;
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    cout << "evaluation done" << endl;

    decryptor.decrypt(temp, plain_result);
    encoder.decode(plain_result, result);
    //cout << "ctx  = " << result[0] << endl;

    cout << "Actual : " << result[0] << ", Expected : " << expected_result << ", diff : " << abs(result[0] - expected_result) << endl;
}


int main()
{

    int degree = 0;
    cout << "Enter Degree: ";
    cin >> degree;

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
            example_polyeval_horner(degree);
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