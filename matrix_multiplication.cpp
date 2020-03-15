#include "fyp_helper.h"

Ciphertext CC_Matrix_Multiplication(Ciphertext ctA, Ciphertext ctB, int dimension, vector<Plaintext> U_sigma_diagonals, vector<Plaintext> U_tau_diagonals, vector<vector<Plaintext>> V_diagonals, vector<vector<Plaintext>> W_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{

    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);

    cout << "----------Step 1----------- " << endl;
    // Step 1-1
    ctA_result[0] = Linear_Transform_Plain(ctA, U_sigma_diagonals, gal_keys, params);

    // Step 1-2
    ctB_result[0] = Linear_Transform_Plain(ctB, U_tau_diagonals, gal_keys, params);

/*
    // Test scale
    cout << "\nSCALE TEST -----------:" << endl;
    for (int i = 0; i < dimension; i++)
    {
        cout << "CTA scale at i = " << i << ":\t" << log2(ctA_result[i].scale()) << endl;
        cout << "CTB scale at i = " << i << ":\t" << log2(ctB_result[i].scale()) << endl;
    }
*/
    // Step 2
    cout << "----------Step 2----------- " << endl;

    for (int k = 1; k < dimension; k++)
    {
        cout << "Linear Transf at k = " << k;
        ctA_result[k] = Linear_Transform_Plain(ctA_result[0], V_diagonals[k - 1], gal_keys, params);
        ctB_result[k] = Linear_Transform_Plain(ctB_result[0], W_diagonals[k - 1], gal_keys, params);
        cout << "..... Done" << endl;
    }

/*
    // Test scale
    for (int i = 0; i < dimension; i++)
    {
        cout << "CTA scale at i = " << i << ":\t" << log2(ctA_result[i].scale()) << endl;
        cout << "CTB scale at i = " << i << ":\t" << log2(ctB_result[i].scale()) << endl;
    }
    // Test Chain
    cout << "\nCHAIN TEST -----------:" << endl;
    for (int i = 0; i < dimension; i++)
    {
        cout << "chain index A at i = " << i << ":\t" << context->get_context_data(ctA_result[i].parms_id())->chain_index() << endl;
        cout << "chain index B at i = " << i << ":\t" << context->get_context_data(ctB_result[i].parms_id())->chain_index() << endl;
    }

    cout << "context data total coeff modulus bit count = " << context->get_context_data(U_sigma_diagonals[0].parms_id())->total_coeff_modulus_bit_count() << endl;
*/
    // Step 3
    cout << "----------Step 3----------- " << endl;

    // Test Rescale
    cout << "RESCALE--------" << endl;
    for (int i = 1; i < dimension; i++)
    {
        evaluator.rescale_to_next_inplace(ctA_result[i]);
        evaluator.rescale_to_next_inplace(ctB_result[i]);
    }

    /*
    // Test scale
    for (int i = 0; i < dimension; i++)
    {
        cout << "CTA scale at i = " << i << ":\t" << log2(ctA_result[i].scale()) << endl;
        cout << "CTB scale at i = " << i << ":\t" << log2(ctB_result[i].scale()) << endl;
    }

    cout << "Exact scale" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    for (int i = 0; i < dimension; i++)
    {
        cout << "\t Exact scale in ctA at i = " << i << ":\t" << ctA_result[i].scale() << endl;
        cout << "\t Exact scale in ctB at i = " << i << ":\t" << ctB_result[i].scale() << endl;
    }
    cout << endl;
    cout.copyfmt(old_fmt);

    // Test Chain
    cout << "\nCHAIN TEST -----------:" << endl;
    for (int i = 0; i < dimension; i++)
    {
        cout << "chain index A at i = " << i << ":\t" << context->get_context_data(ctA_result[i].parms_id())->chain_index() << endl;
        cout << "chain index B at i = " << i << ":\t" << context->get_context_data(ctB_result[i].parms_id())->chain_index() << endl;
    }
*/
    Ciphertext ctAB;
    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);

    // cout << "TEST" << endl;
    // cout << "CTAB scale :\t" << log2(ctAB.scale()) << endl;
    // cout << "CTAB chain index :\t" << context->get_context_data(ctAB.parms_id())->chain_index() << endl;

    // Mod switch CTAB
    // cout << "MOD SWITCH CTAB:" << endl;
    evaluator.mod_switch_to_next_inplace(ctAB);
    // cout << "CTAB chain index :\t" << context->get_context_data(ctAB.parms_id())->chain_index() << endl;

    // Manual scale set
    for (int i = 1; i < dimension; i++)
    {
        ctA_result[i].scale() = pow(2, 80);
        ctB_result[i].scale() = pow(2, 80);
    }

    for (int k = 1; k < dimension; k++)
    {
        cout << "Iteration k = " << k << endl;
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }

    return ctAB;
}

void Matrix_Multiplication(size_t poly_modulus_degree, int dimension)
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

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);

    // Create Scale
    double scale = pow(2.0, 40);

    vector<vector<double>> pod_matrix1_set1(dimension, vector<double>(dimension));
    vector<vector<double>> pod_matrix2_set1(dimension, vector<double>(dimension));

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

    filler = 1;
    // Matrix 2
    for (int i = 0; i < dimension; i++)
    {
        for (int j = 0; j < dimension; j++)
        {
            pod_matrix2_set1[i][j] = filler;
            // r = ((double)rand() / (RAND_MAX));
            filler++;
        }
    }

    cout << "Matrix 2:" << endl;
    print_full_matrix(pod_matrix2_set1, 0);

    int dimensionSq = pow(dimension, 2);

    // Get U_sigma for first matrix
    vector<vector<double>> U_sigma = get_U_sigma(pod_matrix1_set1);
    cout << "\nU_sigma:" << endl;
    print_full_matrix(U_sigma, 0);

    // Get U_tau for second matrix
    vector<vector<double>> U_tau = get_U_tau(pod_matrix1_set1);
    cout << "\nU_tau:" << endl;
    print_full_matrix(U_tau, 0);

    // Get V_k (3D matrix)
    vector<vector<vector<double>>> V_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k[i - 1] = get_V_k(pod_matrix1_set1, i);
        cout << "\nV_" << to_string(i) << ":" << endl;
        print_full_matrix(V_k[i - 1], 0);
    }

    // Get W_k (3D matrix)
    vector<vector<vector<double>>> W_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k[i - 1] = get_W_k(pod_matrix1_set1, i);
        cout << "\nW_" << to_string(i) << ":" << endl;
        print_full_matrix(W_k[i - 1], 0);
    }

    // Get Diagonals for U_sigma
    vector<vector<double>> U_sigma_diagonals = get_all_diagonals(U_sigma);
    cout << "U_sigma Diagonal Matrix:" << endl;
    print_full_matrix(U_sigma_diagonals, 0);

    // Test ADD EPSILON
    double epsilon = 0.00000001;
    for (int i = 0; i < dimensionSq; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            U_sigma_diagonals[i][j] += epsilon;
        }
    }

    // Get Diagonals for U_tau
    vector<vector<double>> U_tau_diagonals = get_all_diagonals(U_tau);

    // Test ADD EPSILON
    for (int i = 0; i < dimensionSq; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            U_tau_diagonals[i][j] += epsilon;
        }
    }

    // Get Diagonals for V_k
    vector<vector<vector<double>>> V_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k_diagonals[i - 1] = get_all_diagonals(V_k[i - 1]);
    }

    // Test ADD EPSILON
    for (int i = 0; i < dimension - 1; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            for (int k = 0; k < dimensionSq; k++)
            {

                V_k_diagonals[i][j][k] += epsilon;
            }
        }
    }

    // Get Diagonals for W_k
    vector<vector<vector<double>>> W_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k_diagonals[i - 1] = get_all_diagonals(W_k[i - 1]);
    }

    // Test ADD EPSILON
    for (int i = 0; i < dimension - 1; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            for (int k = 0; k < dimensionSq; k++)
            {

                W_k_diagonals[i][j][k] += epsilon;
            }
        }
    }

    // --------------- ENCODING ----------------
    // Encode U_sigma diagonals
    vector<Plaintext> U_sigma_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_sigma_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_sigma_diagonals[i], scale, U_sigma_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode U_tau diagonals
    vector<Plaintext> U_tau_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_tau_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_tau_diagonals[i], scale, U_tau_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode V_k diagonals
    vector<vector<Plaintext>> V_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding V_K_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(V_k_diagonals[i - 1][j], scale, V_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode W_k
    vector<vector<Plaintext>> W_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding W_k_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(W_k_diagonals[i - 1][j], scale, W_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode Matrices
    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    cout << "\nEncoding Matrix 1...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // Encode Matrix 2
    vector<Plaintext> plain_matrix2_set1(dimension);
    cout << "\nEncoding Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix2_set1[i], scale, plain_matrix2_set1[i]);
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

    // Encrypt Matrix 2
    vector<Ciphertext> cipher_matrix2_set1(dimension);
    cout << "\nEncrypting Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    cout << "\nMatrix Encoding Matrix 1...";
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, params);
    cout << "Done" << endl;

    // Matrix Encode Matrix 2
    cout << "\nMatrix Encoding Matrix 2...";
    Ciphertext cipher_encoded_matrix2_set1 = C_Matrix_Encode(cipher_matrix2_set1, gal_keys, params);
    cout << "Done" << endl;

/*
    // Test Matrix Encoding
    Plaintext test_matrix_encoding;
    decryptor.decrypt(cipher_encoded_matrix1_set1, test_matrix_encoding);
    vector<double> test_matrix_encoding_result(dimensionSq);
    ckks_encoder.decode(test_matrix_encoding, test_matrix_encoding_result);

    cout << "Decoded Matrix : " << endl;
    cout << "\t[";
    for (int i = 0; i < dimensionSq - 1; i++)
    {
        cout << test_matrix_encoding_result[i] << ", ";
    }
    cout << test_matrix_encoding_result[dimensionSq - 1] << "]" << endl;
*/
    // --------------- MATRIX MULTIPLICATION ----------------
    cout << "\nMatrix Multiplication...";
    cout << "test " << endl;
    Ciphertext ct_result = CC_Matrix_Multiplication(cipher_encoded_matrix1_set1, cipher_encoded_matrix2_set1, dimension, U_sigma_diagonals_plain, U_tau_diagonals_plain, V_k_diagonals_plain, W_k_diagonals_plain, gal_keys, params);
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
        if (i % 4 == 0)
        {
            cout << "\n\t";
        }
        cout << result_matrix[i] << ", ";
    }
    cout << endl;
    
    /*
    cout << "------------ TESTING ------------" << endl;
    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);

    cout << "----------Step 1----------- " << endl;
    // Step 1-1
    ctA_result[0] = Linear_Transform_Plain(cipher_encoded_matrix1_set1, U_sigma_diagonals_plain, gal_keys, params);

    // Step 1-2
    ctB_result[0] = Linear_Transform_Plain(cipher_encoded_matrix2_set1, U_tau_diagonals_plain, gal_keys, params);

    // TEST CTA _ RESULT [0]
    Plaintext cta_0;
    decryptor.decrypt(ctA_result[0], cta_0);
    vector<double> cta_0_res;
    ckks_encoder.decode(cta_0, cta_0_res);

    cout << "Resulting matrix cta[0]: ";
    for (int i = 0; i < dimensionSq; i++)
    {
        if (i % 4 == 0)
        {
            cout << "\n\t";
        }
        cout << cta_0_res[i] << ", ";
    }
    cout << endl;

    // TEST CTB _ RESULT [0]
    Plaintext ctb_0;
    decryptor.decrypt(ctB_result[0], ctb_0);
    vector<double> ctb_0_res;
    ckks_encoder.decode(ctb_0, ctb_0_res);

    cout << "Resulting matrix ctb[0]: ";
    for (int i = 0; i < dimensionSq; i++)
    {
        if (i % 4 == 0)
        {
            cout << "\n\t";
        }
        cout << ctb_0_res[i] << ", ";
    }
    cout << endl;

    // Step 2
    cout << "----------Step 2----------- " << endl;

    for (int k = 1; k < dimension; k++)
    {
        cout << "Linear Transf at k = " << k;
        ctA_result[k] = Linear_Transform_Plain(ctA_result[0], V_k_diagonals_plain[k - 1], gal_keys, params);
        ctB_result[k] = Linear_Transform_Plain(ctB_result[0], W_k_diagonals_plain[k - 1], gal_keys, params);
        cout << "..... Done" << endl;
    }

    // Step 3
    cout << "----------Step 3----------- " << endl;

    // Test Rescale
    cout << "RESCALE--------" << endl;
    for (int i = 1; i < dimension; i++)
    {
        evaluator.rescale_to_next_inplace(ctA_result[i]);
        evaluator.rescale_to_next_inplace(ctB_result[i]);
    }

    Ciphertext ctAB;

    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);

    evaluator.mod_switch_to_next_inplace(ctAB);

    // Manual scale set
    for (int i = 1; i < dimension; i++)
    {
        ctA_result[i].scale() = pow(2, 80);
        ctB_result[i].scale() = pow(2, 80);
    }

    for (int k = 1; k < dimension; k++)
    {
        cout << "Iteration k = " << k << endl;
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }
    */
}

int main()
{

    Matrix_Multiplication(8192 * 2, 4);

    return 0;
}
