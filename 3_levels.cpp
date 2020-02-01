#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main()
{
    cout << "\n--------- Levels Demo ---------\n"
         << endl;

    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);

    // Use a of coeff_modulus of 5 primes of sizes 50, 30, 30, 50 and bits
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50, 50}));

    // 20 bit poly mod degree
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    auto context = SEALContext::Create(params);

    cout << "Print the modulus switching chain" << endl;

    // Print the key level parameter info
    auto context_data = context->key_context_data();
    cout << "\tLevel (chain index): " << context_data->chain_index() << endl;
    // cout << "\tparms_id: " << context_data->parms_id() << endl;
    cout << "\tcoeff_modulus primes: ";
    cout << hex;
    for (const auto &prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << dec << endl;
    cout << "\\" << endl;
    cout << " \\-->";

    // Iterate over the remaining levels
    context_data = context->first_context_data();
    while (context_data)
    {
        cout << " Level (chain index): " << context_data->chain_index();
        if (context_data->parms_id() == context->first_parms_id())
        {
            cout << " ...... first_context_data()" << endl;
        }
        else if (context_data->parms_id() == context->last_parms_id())
        {
            cout << " ...... last_context_data()" << endl;
        }
        else
        {
            cout << endl;
        }
        // cout << "      parms_id: " << context_data->parms_id() << endl;
        cout << "      coeff_modulus primes: ";
        cout << hex;
        for (const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->";

        /*
        Step forward in the chain.
        */
        context_data = context_data->next_context_data();
    }

    cout << "End of chain reached\n"
         << endl;

    // Generate keys
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    cout << "Perform modulus switching on cipher" << endl;
    context_data = context->first_context_data();
    cout << "---->";

    while (context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
        // cout << "      parms_id of encrypted: " << cipher.parms_id() << endl;
        cout << "      Noise budget at this level: "
             << decryptor.invariant_noise_budget(cipher) << " bits" << endl;
        cout << "\\" << endl;
        cout << " \\-->";
        evaluator.mod_switch_to_next_inplace(cipher);
        context_data = context_data->next_context_data();
    }
    cout << " Level (chain index): " << context_data->chain_index() << endl;
    // cout << "      parms_id of encrypted: " << cipher.parms_id() << endl;
    cout << "      Noise budget at this level: "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;
    cout << "\\" << endl;
    cout << " \\-->";
    cout << " End of chain reached" << endl
         << endl;

    cout << "Decrypt still works after modulus switching." << endl;
    decryptor.decrypt(cipher, plain);
    cout << "    + Decryption of encrypted: " << plain.to_string() << endl;

    cout << "\tComputation is more efficient with modulus switching." << endl;
    cout << "Compute the 8th power." << endl;
    encryptor.encrypt(plain, cipher);
    cout << "    + Noise budget fresh:                   "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;
    evaluator.square_inplace(cipher);
    evaluator.relinearize_inplace(cipher, relin_keys);
    cout << "    + Noise budget of the 2nd power:         "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;
    evaluator.square_inplace(cipher);
    evaluator.relinearize_inplace(cipher, relin_keys);
    cout << "    + Noise budget of the 4th power:         "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;

    evaluator.mod_switch_to_next_inplace(cipher);
    cout << "    + Noise budget after modulus switching:  "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;

    evaluator.square_inplace(cipher);
    evaluator.relinearize_inplace(cipher, relin_keys);
    cout << "    + Noise budget of the 8th power:         "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;
    evaluator.mod_switch_to_next_inplace(cipher);
    cout << "    + Noise budget after modulus switching:  "
         << decryptor.invariant_noise_budget(cipher) << " bits" << endl;

    decryptor.decrypt(cipher, plain);
    cout << "    + Decryption of the 8th power (hexadecimal) ...... Correct." << endl;
    cout << "    " << plain.to_string() << endl
         << endl;

    return 0;
}