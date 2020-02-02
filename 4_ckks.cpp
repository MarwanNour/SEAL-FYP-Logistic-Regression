#include "seal/seal.h"
#include <iostream>
#include <iomanip>

using namespace std;
using namespace seal;

// Helper function that prints a vector of floats
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

int main()
{
    cout << "------- CKKS ---------\n"
         << endl;

    // Set up the parameters
    EncryptionParameters params(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    double scale = pow(2.0, 40);
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input_vec;
    input_vec.reserve(slot_count);

    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input_vec.push_back(curr_point);
    }

    cout << "Input Vector: " << endl;
    print_vector(input_vec, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 :\n"
         << endl;

    // Create Plaintexts and encode them in CKKSEncoder
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    cout << "Encode input vectors" << endl;
    encoder.encode(input_vec, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    // To compute x^3, we need to compute first x^2 and relinearize.
    Ciphertext x3_encrypted;
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "\t+ Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    // Rescale
    cout << "Rescale x^2: " << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "\t+ Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    // Compute PI*x and rescale
    cout << "Compute and rescale PI*x" << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "\t+ Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "\t+ Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;

    // Compute, relin and rescale (PI*x)*x^2
    cout << "Compute, relin, and rescale (PI*x)*x^2" << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "\t+ Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "\t+ Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    // Compute and rescale 0.4*x
    cout << "Compute and rescale 0.4*x" << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "\t+ Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "\t+ Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    cout << "\nParameters use by all three terms are different:" << endl;
    cout << "\t+ Modulus chain index for x3_encrypted: "
         << context->get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "\t+ Modulus chain index for x1_encrypted: "
         << context->get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "\t+ Modulus chain index for plain_coeff0: "
         << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. We denote the
    primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
    the special modulus and is not involved in rescalings. After the computations
    above the scales in ciphertexts are:

        - Product x^2 has scale 2^80 and is at level 2;
        - Product PI*x has scale 2^80 and is at level 2;
        - We rescaled both down to scale 2^80/P_2 and level 1;
        - Product PI*x^3 has scale (2^80/P_2)^2;
        - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
        - Product 0.4*x has scale 2^80;
        - We rescaled it down to scale 2^80/P_2 and level 1;
        - The contant term 1 has scale 2^40 and is at level 2.

    Although the scales of all three terms are approximately 2^40, their exact
    values are different, hence they cannot be added together.
    */

    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are many ways to fix this problem. Since P_2 and P_1 are really close
    to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
    same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
    scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
    This should not result in any noticeable error.

    Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
    with 0.4*x, and finally rescale. In this case we would need to additionally
    make sure to encode 1 with appropriate encryption parameters (parms_id).

    In this example we will use the first (simplest) approach and simply change
    the scale of PI*x^3 and 0.4*x to 2^40.
    */

    cout << "Normalize scales to 2^40" << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme, allowing us to switch away parts
    of the coefficient modulus when it is simply not needed.
    */

    cout << "Normalize encryption parameters to the lowest levvel" << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    // All three ciphertexts are now compatible and can be added

    cout << "Compute PI*x^3 + 0.4*x + 1" << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    // Print the true result
    cout << "Decrypt and decode PI*x^3 + 0.4*x + 1" << endl;
    cout << "\t+ Expected result: " << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input_vec.size(); i++)
    {
        double x = input_vec[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

    // Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "\t+ Computed result: " << endl;
    print_vector(result, 3, 7);
    
    return 0;
}