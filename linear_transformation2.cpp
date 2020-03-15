#include "fyp_helper.h"


void PMatrix_CVector_Multiplication(size_t poly_modulus_degree, int dimension)
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
    // Create scale
    cout << "Coeff Modulus Back Value: " << params.coeff_modulus().back().value() << endl;
    double scale = pow(2.0, 40);

    // Set output file
    string filename = "linear_transf_p" + to_string(poly_modulus_degree) + "_d" + to_string(dimension) + ".dat";
    ofstream outf(filename);

    // Handle file error
    if (!outf)
    {
        cerr << "Couldn't open file: " << filename << endl;
        exit(1);
    }

    // Set output script
    string script = "linear_transf_plot_p" + to_string(poly_modulus_degree) + "_d" + to_string(dimension) + ".py";
    ofstream outscript(script);

    // Handle script error
    if (!outscript)
    {
        cerr << "Couldn't open file: " << script << endl;
        exit(1);
    }

    // Write to Script
    outscript << "import matplotlib.pyplot as plt" << endl;
    outscript << "labels = 'Encode', 'Encrypt', 'Computation', 'Decode', 'Decrypt'" << endl;
    outscript << "colors = ['gold', 'green', 'lightskyblue', 'red', 'violet']" << endl;
    outscript << "sizes = [";

    cout << "Dimension : " << dimension << endl
         << endl;

    vector<vector<double>> pod_matrix_set1(dimension, vector<double>(dimension));
    vector<double> pod_vec_set1(dimension);

    // Fill input matrices

    double r = ((double)rand() / (RAND_MAX));

    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix_set1[i][j] = r;
            r = ((double)rand() / (RAND_MAX));
        }
    }

    for (int i = 0; i < dimension; i++)
    {
        r = ((double)rand() / (RAND_MAX));
        pod_vec_set1[i] = r;
    }

    cout << "Matrix:" << endl;
    print_partial_matrix(pod_matrix_set1);
    cout << "Vector:" << endl;
    print_partial_vector(pod_vec_set1, dimension);

    // Get all diagonals
    vector<vector<double>> all_diagonal_set1(dimension, vector<double>(dimension));

    for (int i = 0; i < dimension; i++)
    {
        all_diagonal_set1[i] = get_diagonal(i, pod_matrix_set1);
    }

    cout << "Diagonal Expected:" << endl;
    print_partial_matrix(all_diagonal_set1);

    // Encode Matrices into vectors with Diagonals
    vector<Plaintext> plain_matrix_set1(dimension);
    Plaintext plain_vec_set1;
    vector<Plaintext> plain_diagonal_set1(dimension);

    auto start_encode = chrono::high_resolution_clock::now();
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix_set1[i], scale, plain_matrix_set1[i]);
        ckks_encoder.encode(pod_vec_set1, scale, plain_vec_set1);
        ckks_encoder.encode(all_diagonal_set1[i], scale, plain_diagonal_set1[i]);
    }
    auto stop_encode = chrono::high_resolution_clock::now();

    cout << "Encoding is Complete" << endl;
    auto duration_encode = chrono::duration_cast<chrono::microseconds>(stop_encode - start_encode);
    cout << "Encode Duration:\t" << duration_encode.count() << endl;
    outscript << duration_encode.count() << ", ";

    // Encrypt the matrices with Diagonals
    vector<Ciphertext> cipher_matrix_set1(dimension);
    Ciphertext cipher_vec_set1;
    vector<Ciphertext> cipher_diagonal_set1(dimension);

    auto start_encrypt = chrono::high_resolution_clock::now();
    for (unsigned int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix_set1[i], cipher_matrix_set1[i]);
        encryptor.encrypt(plain_vec_set1, cipher_vec_set1);
        encryptor.encrypt(plain_diagonal_set1[i], cipher_diagonal_set1[i]);
    }
    auto stop_encrypt = chrono::high_resolution_clock::now();

    cout << "Encrypting is Complete" << endl;
    auto duration_encrypt = chrono::duration_cast<chrono::microseconds>(stop_encrypt - start_encrypt);
    cout << "Encrypt Duration:\t" << duration_encrypt.count() << endl;
    outscript << duration_encrypt.count() << ", ";

    // ------------- FIRST COMPUTATION ----------------
    outf << "# index 0" << endl;
    outf << "# C_Vec . P_Mat" << endl;

    // Test LinearTransform here
    auto start_comp1_set1 = chrono::high_resolution_clock::now();
    Ciphertext ct_prime1_set1 = Linear_Transform_Plain(cipher_matrix_set1[0], plain_diagonal_set1, gal_keys, params);
    auto stop_comp1_set1 = chrono::high_resolution_clock::now();

    auto duration_comp1_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set1 - start_comp1_set1);
    cout << "\nTime to compute C_vec . P_mat: " << duration_comp1_set1.count() << " microseconds" << endl;
    outf << to_string(dimension) << "\t\t" << duration_comp1_set1.count() << endl;
    outscript << duration_comp1_set1.count() << ", ";

    // Decrypt
    Plaintext pt_result1_set1;
    auto start_decrypt = chrono::high_resolution_clock::now();
    decryptor.decrypt(ct_prime1_set1, pt_result1_set1);
    auto stop_decrypt = chrono::high_resolution_clock::now();
    auto duration_decrypt = chrono::duration_cast<chrono::microseconds>(stop_decrypt - start_decrypt);
    cout << "Decrypt Duration:\t" << duration_decrypt.count() << endl;
    outscript << duration_decrypt.count() << ", ";

    // Decode
    vector<double> output_result1_set1;
    auto start_decode = chrono::high_resolution_clock::now();
    ckks_encoder.decode(pt_result1_set1, output_result1_set1);
    auto stop_decode = chrono::high_resolution_clock::now();
    auto duration_decode = chrono::duration_cast<chrono::microseconds>(stop_decode - start_decode);
    cout << "Decode Duration:\t" << duration_decode.count() << endl;
    outscript << duration_decode.count();

    cout << "Linear Transformation:" << endl;
    print_partial_vector(output_result1_set1, dimension);

    // Check result
    cout << "Expected output: " << endl;

    test_Linear_Transformation(dimension, pod_matrix_set1, pod_matrix_set1[0]);

    outf << "\n"
         << endl;
    outf.close();

    outscript << "]" << endl;
    outscript << "plt.pie(sizes, colors=colors, autopct='%.1f')" << endl;
    outscript << "plt.title(\"Linear Transformation Test p" << to_string(poly_modulus_degree) << " d"<< to_string(dimension) <<  "\")" << endl;
    outscript << "plt.legend(labels)" << endl;
    outscript << "plt.tight_layout()" << endl;
    outscript << "plt.axis('equal')" << endl;
    outscript << "plt.show()" << endl;

    outscript.close();
}

int main()
{
    PMatrix_CVector_Multiplication(8192, 2000);

    return 0;
}