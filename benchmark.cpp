#include <iostream>
#include <fstream>
#include <iomanip>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper function that prints a vector of floats
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 4)
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

// Helper function that prints a matrix (vector of vectors)
template <typename T>
inline void print_full_matrix(vector<vector<T>> matrix, int size, int precision = 3)
{
    // save formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);

    for (unsigned int i = 0; i < size; i++)
    {
        cout << "[";
        for (unsigned int j = 0; j < size - 1; j++)
        {
            cout << matrix[i][j] << ", ";
        }
        cout << matrix[i][size - 1];
        cout << "]" << endl;
    }
    cout << endl;
    // restore old cout formatting
    cout.copyfmt(old_fmt);
}

template <typename T>
inline void print_partial_matrix(vector<vector<T>> matrix, int size, int precision = 3)
{
    // save formatting for cout
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(precision);

    int print_size = 4;

    // print first 4 elements
    for (unsigned int row = 0; row < print_size; row++)
    {
        cout << "\t[";
        for (unsigned int col = 0; col < print_size; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << "..., ";
        for (unsigned int col = size - print_size; col < size - 1; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << matrix[row][size - 1];
        cout << "]" << endl;
    }
    cout << "\t..." << endl;

    for (unsigned int row = size - print_size; row < size; row++)
    {
        cout << "\t[";
        for (unsigned int col = 0; col < print_size; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << "..., ";
        for (unsigned int col = size - print_size; col < size - 1; col++)
        {
            cout << matrix[row][col] << ", ";
        }
        cout << matrix[row][size - 1];
        cout << "]" << endl;
    }

    cout << endl;
    // restore old cout formatting
    cout.copyfmt(old_fmt);
}

void ckksBenchmark(size_t poly_modulus_degree)
{
    cout << "------CKKS TEST------\n"
         << endl;

    // Set params
    EncryptionParameters params(scheme_type::CKKS);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "Slot count : " << slot_count << endl;

    // Set output file
    string filename = "bench_" + to_string(poly_modulus_degree) + ".dat";
    ofstream outf(filename);

    // Handle file error
    if (!outf)
    {
        cerr << "Couldn't open file: " << filename << endl;
        exit(1);
    }

    // Set output script
    string script = "script_" + to_string(poly_modulus_degree) + ".p";
    ofstream outscript(script);

    // Handle script error
    if (!outscript)
    {
        cerr << "Couldn't open file: " << script << endl;
        exit(1);
    }
    // Write to script
    outscript << "# Set the output terminal" << endl;
    outscript << "set terminal canvas" << endl;
    outscript << "set output \"canvas_" << to_string(poly_modulus_degree) << ".html\"" << endl;
    outscript << "set title \"CKKS Benchmark " << to_string(poly_modulus_degree) << "\"" << endl;
    outscript << "set xlabel 'Input Vector Size'" << endl;
    outscript << "set ylabel 'Time (microseconds)'" << endl;

    outscript << "\n# Set the styling " << endl;
    outscript << "set style line 1\\\n"
              << "linecolor rgb '#0060ad'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 7 pointsize 1.5\n"
              << endl;

    outscript << "set style line 2\\\n"
              << "linecolor rgb '#dd181f'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 5 pointsize 1.5\n"
              << endl;

    outscript << "set style line 3\\\n"
              << "linecolor rgb '#00FF00'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 6 pointsize 1.5\n"
              << endl;

    outscript << "set style line 4\\\n"
              << "linecolor rgb '#EC00EC'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 4 pointsize 1.5\n"
              << endl;

    outscript << "\nplot 'bench_" << to_string(poly_modulus_degree) << ".dat' index 0 title \"C1 + P2\" with linespoints ls 1, \\\n"
              << "'' index 1 title \"C1 + C2\"  with linespoints ls 2, \\\n"
              << "'' index 2 title \"C1 * P2\"  with linespoints ls 3, \\\n"
              << "'' index 3 title \"C1 * C2\"  with linespoints ls 4";
    // Close script
    outscript.close();

    /*
    3 sets of vectors:
    1st set: sizes = 10
    2nd set: sizes = 100
    3rd set: sizes = 1000
    */

    // ------------- FIRST SET -------------
    // First vector
    vector<double> pod_vec1_set1(10, 0);
    for (unsigned int i = 0; i < 10; i++)
    {
        pod_vec1_set1[i] = static_cast<double>(i);
    }
    print_vector(pod_vec1_set1);
    // Second vector
    vector<double> pod_vec2_set1(10, 0);
    for (unsigned int i = 0; i < 10; i++)
    {
        pod_vec2_set1[i] = static_cast<double>((i % 2) + 1);
    }
    print_vector(pod_vec2_set1);

    // -------------- SECOND SET -------------
    // First vector
    vector<double> pod_vec1_set2(100, 0);
    for (unsigned int i = 0; i < 100; i++)
    {
        pod_vec1_set2[i] = static_cast<double>(i);
    }
    print_vector(pod_vec1_set2);
    // Second vector
    vector<double> pod_vec2_set2(100, 0);
    for (unsigned int i = 0; i < 100; i++)
    {
        pod_vec2_set2[i] = static_cast<double>((i % 2) + 1);
    }
    print_vector(pod_vec2_set2);

    // -------------- THIRD SET -------------
    // First vector
    vector<double> pod_vec1_set3(1000, 0);
    for (unsigned int i = 0; i < 1000; i++)
    {
        pod_vec1_set3[i] = static_cast<double>(i);
    }
    print_vector(pod_vec1_set3);
    // Second vector
    vector<double> pod_vec2_set3(1000, 0);
    for (unsigned int i = 0; i < 1000; i++)
    {
        pod_vec2_set3[i] = static_cast<double>((i % 2) + 1);
    }
    print_vector(pod_vec2_set3);

    // Encode all vectors
    Plaintext plain_vec1_set1, plain_vec2_set1, plain_vec1_set2, plain_vec2_set2, plain_vec1_set3, plain_vec2_set3;
    double scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));
    // First set encode
    ckks_encoder.encode(pod_vec1_set1, scale, plain_vec1_set1);
    ckks_encoder.encode(pod_vec2_set1, scale, plain_vec2_set1);
    // Second set encode
    ckks_encoder.encode(pod_vec1_set2, scale, plain_vec1_set2);
    ckks_encoder.encode(pod_vec2_set2, scale, plain_vec2_set2);
    // Third set encode
    ckks_encoder.encode(pod_vec1_set3, scale, plain_vec1_set3);
    ckks_encoder.encode(pod_vec2_set3, scale, plain_vec2_set3);

    // Encrypt all vectors
    Ciphertext cipher_vec1_set1, cipher_vec2_set1, cipher_vec1_set2, cipher_vec2_set2, cipher_vec1_set3, cipher_vec2_set3;
    // First set cipher
    encryptor.encrypt(plain_vec1_set1, cipher_vec1_set1);
    encryptor.encrypt(plain_vec2_set1, cipher_vec2_set1);
    // Second set cipher
    encryptor.encrypt(plain_vec1_set2, cipher_vec1_set2);
    encryptor.encrypt(plain_vec2_set2, cipher_vec2_set2);
    // Third set cipher
    encryptor.encrypt(plain_vec1_set3, cipher_vec1_set3);
    encryptor.encrypt(plain_vec2_set3, cipher_vec2_set3);
    // Create Ciphertext Outputs
    Ciphertext cipher_result1_set1, cipher_result1_set2, cipher_result1_set3;
    Ciphertext cipher_result2_set1, cipher_result2_set2, cipher_result2_set3;
    Ciphertext cipher_result3_set1, cipher_result3_set2, cipher_result3_set3;
    Ciphertext cipher_result4_set1, cipher_result4_set2, cipher_result4_set3;

    // ------------------ (cipher1 + plain2) ---------------
    cout << "\n------------------ FIRST OPERATION ------------------\n"
         << endl;
    outf << "# index 0" << endl;
    outf << "# C1 + P2" << endl;

    // Compute (cipher1 + plain2) for set 1
    cout << "Compute (cipher1 + plain2) for set 1" << endl;

    // TIME START
    auto start_comp1_set1 = chrono::high_resolution_clock::now();

    evaluator.add_plain(cipher_vec1_set1, plain_vec2_set1, cipher_result1_set1);

    // TIME END
    auto stop_comp1_set1 = chrono::high_resolution_clock::now();
    auto duration_comp1_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set1 - start_comp1_set1);

    // Decrypt and Decode
    Plaintext plain_result1_set1;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result1_set1, plain_result1_set1);
    vector<double> vec_result1_set1;
    ckks_encoder.decode(plain_result1_set1, vec_result1_set1);
    print_vector(vec_result1_set1);

    cout << "\nTime to compute (cipher1 + plain2): " << duration_comp1_set1.count() << " microseconds" << endl;
    outf << "10\t\t" << duration_comp1_set1.count() << endl;

    // Compute (cipher1 + plain2) for set 2
    cout << "Compute (cipher1 + plain2) for set 2" << endl;

    // TIME START
    auto start_comp1_set2 = chrono::high_resolution_clock::now();

    evaluator.add_plain(cipher_vec1_set2, plain_vec2_set2, cipher_result1_set2);

    // TIME END
    auto stop_comp1_set2 = chrono::high_resolution_clock::now();
    auto duration_comp1_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set2 - start_comp1_set2);

    // Decrypt and Decode
    Plaintext plain_result1_set2;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result1_set2, plain_result1_set2);
    vector<double> vec_result1_set2;
    ckks_encoder.decode(plain_result1_set2, vec_result1_set2);
    print_vector(vec_result1_set2);

    cout << "\nTime to compute (cipher1 + plain2): " << duration_comp1_set2.count() << " microseconds" << endl;
    outf << "100\t\t" << duration_comp1_set2.count() << endl;

    // Compute (cipher1 + plain2) for set 3
    cout << "Compute (cipher1 + plain2) for set 3" << endl;

    // TIME START
    auto start_comp1_set3 = chrono::high_resolution_clock::now();

    evaluator.add_plain(cipher_vec1_set3, plain_vec2_set3, cipher_result1_set3);

    // TIME END
    auto stop_comp1_set3 = chrono::high_resolution_clock::now();
    auto duration_comp1_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set3 - start_comp1_set3);

    // Decrypt and Decode
    Plaintext plain_result1_set3;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result1_set3, plain_result1_set3);
    vector<double> vec_result1_set3;
    ckks_encoder.decode(plain_result1_set3, vec_result1_set3);
    print_vector(vec_result1_set3);

    cout << "\nTime to compute (cipher1 + plain2): " << duration_comp1_set3.count() << " microseconds" << endl;
    outf << "1000\t\t" << duration_comp1_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;
    // ------------------ (cipher1 + cipher2) ---------------
    cout << "\n------------------ SECOND OPERATION ------------------\n"
         << endl;
    // Compute (cipher1 + cipher2) for set 1
    cout << "Compute (cipher1 + cipher2) for set 1" << endl;
    outf << "# index 1" << endl;
    outf << "# C1 + C2" << endl;

    // TIME START
    auto start_comp2_set1 = chrono::high_resolution_clock::now();

    evaluator.add(cipher_vec1_set1, cipher_vec2_set1, cipher_result2_set1);

    // TIME END
    auto stop_comp2_set1 = chrono::high_resolution_clock::now();
    auto duration_comp2_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set1 - start_comp2_set1);

    // Decrypt and Decode
    Plaintext plain_result2_set1;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result2_set1, plain_result2_set1);
    vector<double> vec_result2_set1;
    ckks_encoder.decode(plain_result2_set1, vec_result2_set1);
    print_vector(vec_result2_set1);

    cout << "\nTime to compute (cipher1 + cipher2): " << duration_comp2_set1.count() << " microseconds" << endl;
    outf << "10\t\t" << duration_comp2_set1.count() << endl;

    // Compute (cipher1 + cipher2) for set 2
    cout << "Compute (cipher1 + cipher2) for set 2" << endl;

    // TIME START
    auto start_comp2_set2 = chrono::high_resolution_clock::now();

    evaluator.add(cipher_vec1_set2, cipher_vec2_set2, cipher_result2_set2);

    // TIME END
    auto stop_comp2_set2 = chrono::high_resolution_clock::now();
    auto duration_comp2_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set2 - start_comp2_set2);

    // Decrypt and Decode
    Plaintext plain_result2_set2;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result2_set2, plain_result2_set2);
    vector<double> vec_result2_set2;
    ckks_encoder.decode(plain_result2_set2, vec_result2_set2);
    print_vector(vec_result2_set2);

    cout << "\nTime to compute (cipher1 + cipher2): " << duration_comp2_set2.count() << " microseconds" << endl;
    outf << "100\t\t" << duration_comp2_set2.count() << endl;

    // Compute (cipher1 + cipher2) for set 3
    cout << "Compute (cipher1 + cipher2) for set 3" << endl;

    // TIME START
    auto start_comp2_set3 = chrono::high_resolution_clock::now();

    evaluator.add(cipher_vec1_set3, cipher_vec2_set3, cipher_result2_set3);

    // TIME END
    auto stop_comp2_set3 = chrono::high_resolution_clock::now();
    auto duration_comp2_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set3 - start_comp2_set3);

    // Decrypt and Decode
    Plaintext plain_result2_set3;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result2_set3, plain_result2_set3);
    vector<double> vec_result2_set3;
    ckks_encoder.decode(plain_result2_set3, vec_result2_set3);
    print_vector(vec_result2_set3);

    cout << "\nTime to compute (cipher1 + cipher2): " << duration_comp2_set3.count() << " microseconds" << endl;
    outf << "1000\t\t" << duration_comp2_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // ------------------ (cipher1 * plain2) ---------------
    cout << "\n------------------ THIRD OPERATION ------------------\n"
         << endl;

    // Compute (cipher1 + plain2) for set 1
    cout << "Compute (cipher1 * plain2) for set 1" << endl;
    outf << "# index 2" << endl;
    outf << "# C1 * P2" << endl;
    // TIME START
    auto start_comp3_set1 = chrono::high_resolution_clock::now();

    evaluator.multiply_plain(cipher_vec1_set1, plain_vec2_set1, cipher_result3_set1);

    // TIME END
    auto stop_comp3_set1 = chrono::high_resolution_clock::now();
    auto duration_comp3_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp3_set1 - start_comp3_set1);

    // Decrypt and Decode
    Plaintext plain_result3_set1;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result3_set1, plain_result3_set1);
    vector<double> vec_result3_set1;
    ckks_encoder.decode(plain_result3_set1, vec_result3_set1);
    print_vector(vec_result3_set1);

    cout << "\nTime to compute (cipher1 * plain2): " << duration_comp3_set1.count() << " microseconds" << endl;
    outf << "10\t\t" << duration_comp3_set1.count() << endl;

    // Compute (cipher1 * plain2) for set 2
    cout << "Compute (cipher1 * plain2) for set 2" << endl;

    // TIME START
    auto start_comp3_set2 = chrono::high_resolution_clock::now();

    evaluator.multiply_plain(cipher_vec1_set2, plain_vec2_set2, cipher_result3_set2);

    // TIME END
    auto stop_comp3_set2 = chrono::high_resolution_clock::now();
    auto duration_comp3_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp3_set2 - start_comp3_set2);

    // Decrypt and Decode
    Plaintext plain_result3_set2;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result3_set2, plain_result3_set2);
    vector<double> vec_result3_set2;
    ckks_encoder.decode(plain_result3_set2, vec_result3_set2);
    print_vector(vec_result3_set2);

    cout << "\nTime to compute (cipher1 * plain2): " << duration_comp3_set2.count() << " microseconds" << endl;
    outf << "100\t\t" << duration_comp3_set2.count() << endl;

    // Compute (cipher1 * plain2) for set 3
    cout << "Compute (cipher1 * plain2) for set 3" << endl;

    // TIME START
    auto start_comp3_set3 = chrono::high_resolution_clock::now();

    evaluator.multiply_plain(cipher_vec1_set3, plain_vec2_set3, cipher_result3_set3);

    // TIME END
    auto stop_comp3_set3 = chrono::high_resolution_clock::now();
    auto duration_comp3_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp3_set3 - start_comp3_set3);

    // Decrypt and Decode
    Plaintext plain_result3_set3;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result3_set3, plain_result3_set3);
    vector<double> vec_result3_set3;
    ckks_encoder.decode(plain_result3_set3, vec_result3_set3);
    print_vector(vec_result3_set3);

    cout << "\nTime to compute (cipher1 * plain2): " << duration_comp3_set3.count() << " microseconds" << endl;
    outf << "1000\t\t" << duration_comp3_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // ------------------ (cipher1 * cipher2) ---------------
    cout << "\n------------------ FOURTH OPERATION ------------------\n"
         << endl;
    // Compute (cipher1 * cipher2) for set 1
    cout << "Compute (cipher1 * cipher2) for set 1" << endl;
    outf << "# index 3" << endl;
    outf << "# C1 * C2" << endl;
    // TIME START
    auto start_comp4_set1 = chrono::high_resolution_clock::now();

    evaluator.multiply(cipher_vec1_set1, cipher_vec2_set1, cipher_result4_set1);

    // TIME END
    auto stop_comp4_set1 = chrono::high_resolution_clock::now();
    auto duration_comp4_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp4_set1 - start_comp4_set1);

    // Decrypt and Decode
    Plaintext plain_result4_set1;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result4_set1, plain_result4_set1);
    vector<double> vec_result4_set1;
    ckks_encoder.decode(plain_result4_set1, vec_result4_set1);
    print_vector(vec_result4_set1);

    cout << "\nTime to compute (cipher1 * cipher2): " << duration_comp4_set1.count() << " microseconds" << endl;
    outf << "10\t\t" << duration_comp4_set1.count() << endl;

    // Compute (cipher1 * cipher2) for set 2
    cout << "Compute (cipher1 * cipher2) for set 2" << endl;

    // TIME START
    auto start_comp4_set2 = chrono::high_resolution_clock::now();

    evaluator.multiply(cipher_vec1_set2, cipher_vec2_set2, cipher_result4_set2);

    // TIME END
    auto stop_comp4_set2 = chrono::high_resolution_clock::now();
    auto duration_comp4_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp4_set2 - start_comp4_set2);

    // Decrypt and Decode
    Plaintext plain_result4_set2;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result4_set2, plain_result4_set2);
    vector<double> vec_result4_set2;
    ckks_encoder.decode(plain_result4_set2, vec_result4_set2);
    print_vector(vec_result4_set2);

    cout << "\nTime to compute (cipher1 * cipher2): " << duration_comp4_set2.count() << " microseconds" << endl;
    outf << "100\t\t" << duration_comp4_set2.count() << endl;

    // Compute (cipher1 * cipher2) for set 3
    cout << "Compute (cipher1 * cipher2) for set 3" << endl;

    // TIME START
    auto start_comp4_set3 = chrono::high_resolution_clock::now();

    evaluator.multiply(cipher_vec1_set3, cipher_vec2_set3, cipher_result4_set3);

    // TIME END
    auto stop_comp4_set3 = chrono::high_resolution_clock::now();
    auto duration_comp4_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp4_set3 - start_comp4_set3);

    // Decrypt and Decode
    Plaintext plain_result4_set3;
    cout << "Decrypt and decode the result" << endl;
    decryptor.decrypt(cipher_result4_set3, plain_result4_set3);
    vector<double> vec_result4_set3;
    ckks_encoder.decode(plain_result4_set3, vec_result4_set3);
    print_vector(vec_result4_set3);

    cout << "\nTime to compute (cipher1 * cipher2): " << duration_comp4_set3.count() << " microseconds" << endl;
    outf << "1000\t\t" << duration_comp4_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // Close the file
    outf.close();
}

void ckksBenchmarkMatrix(size_t poly_modulus_degree)
{
    cout << "------CKKS Matrix TEST------\n"
         << endl;

    // Set params
    EncryptionParameters params(scheme_type::CKKS);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    auto context = SEALContext::Create(params);

    // Generate keys, encryptor, decryptor and evaluator
    KeyGenerator keygen(context);
    PublicKey pk = keygen.public_key();
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Create CKKS encoder
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "Slot count : " << slot_count << endl;

    // Set output file
    string filename = "bench_matrix_" + to_string(poly_modulus_degree) + ".dat";
    ofstream outf(filename);

    // Handle file error
    if (!outf)
    {
        cerr << "Couldn't open file: " << filename << endl;
        exit(1);
    }

    // Set output script
    string script = "script_matrix_" + to_string(poly_modulus_degree) + ".p";
    ofstream outscript(script);

    // Handle script error
    if (!outscript)
    {
        cerr << "Couldn't open file: " << script << endl;
        exit(1);
    }
    // Write to script
    outscript << "# Set the output terminal" << endl;
    outscript << "set terminal canvas" << endl;
    outscript << "set output \"canvas_matrix_" << to_string(poly_modulus_degree) << ".html\"" << endl;
    outscript << "set title \"CKKS Matrix Benchmark " << to_string(poly_modulus_degree) << "\"" << endl;
    outscript << "set xlabel 'Input Matrix Size (NxN)'" << endl;
    outscript << "set ylabel 'Time (microseconds)'" << endl;

    outscript << "\n# Set the styling " << endl;
    outscript << "set style line 1\\\n"
              << "linecolor rgb '#0060ad'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 7 pointsize 1.5\n"
              << endl;

    outscript << "set style line 2\\\n"
              << "linecolor rgb '#dd181f'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 5 pointsize 1.5\n"
              << endl;

    outscript << "set style line 3\\\n"
              << "linecolor rgb '#00FF00'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 6 pointsize 1.5\n"
              << endl;

    outscript << "set style line 4\\\n"
              << "linecolor rgb '#EC00EC'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 4 pointsize 1.5\n"
              << endl;

    outscript << "\nplot 'bench_matrix_" << to_string(poly_modulus_degree) << ".dat' index 0 title \"C1 + P2\" with linespoints ls 1, \\\n"
              << "'' index 1 title \"C1 + C2\"  with linespoints ls 2, \\\n"
              << "'' index 2 title \"C1 * P2\"  with linespoints ls 3, \\\n"
              << "'' index 3 title \"C1 * C2\"  with linespoints ls 4";
    // Close script
    outscript.close();

    // ------------- FIRST SET -------------
    // First Matrix
    int set_size1 = 10;
    vector<vector<double>> pod_matrix1_set1(set_size1, vector<double>(set_size1));
    double k = 0.0;
    for (unsigned int i = 0; i < set_size1; i++)
    {
        for (unsigned int j = 0; j < set_size1; j++)
        {

            pod_matrix1_set1[i][j] = k;
            // cout << "k = " << k;
            k++;
        }
    }

    cout << "Matrix 1 Set 1:\n"
         << endl;
    // print_full_matrix(pod_matrix1_set1, set_size1);
    print_partial_matrix(pod_matrix1_set1, set_size1);

    // Second Matrix
    vector<vector<double>> pod_matrix2_set1(set_size1, vector<double>(set_size1));
    k = 0.0;
    for (unsigned int i = 0; i < set_size1; i++)
    {
        for (unsigned int j = 0; j < set_size1; j++)
        {
            pod_matrix2_set1[i][j] = static_cast<double>((int(k) % 2) + 1);
            k++;
        }
    }
    cout << "Matrix 2 Set 1:\n"
         << endl;

    // print_full_matrix(pod_matrix2_set1, set_size1);
    print_partial_matrix(pod_matrix2_set1, set_size1);
    // ------------- Second SET -------------
    // First Matrix
    int set_size2 = 100;
    vector<vector<double>> pod_matrix1_set2(set_size2, vector<double>(set_size2));
    k = 0.0;
    for (unsigned int i = 0; i < set_size2; i++)
    {
        for (unsigned int j = 0; j < set_size2; j++)
        {

            pod_matrix1_set2[i][j] = k;
            // cout << "k = " << k;
            k++;
        }
    }
    cout << "Matrix 1 Set 2:\n"
         << endl;

    print_partial_matrix(pod_matrix1_set2, set_size2);

    // Second Matrix
    vector<vector<double>> pod_matrix2_set2(set_size2, vector<double>(set_size2));
    k = 0.0;
    for (unsigned int i = 0; i < set_size2; i++)
    {
        for (unsigned int j = 0; j < set_size2; j++)
        {
            pod_matrix2_set2[i][j] = static_cast<double>((int(k) % 2) + 1);
            k++;
        }
    }
    cout << "Matrix 2 Set 2:\n"
         << endl;

    print_partial_matrix(pod_matrix2_set2, set_size2);

    // ------------- THIRD SET -------------
    // First Matrix
    int set_size3 = 1000;
    vector<vector<double>> pod_matrix1_set3(set_size3, vector<double>(set_size3));
    k = 0.0;
    for (unsigned int i = 0; i < set_size3; i++)
    {
        for (unsigned int j = 0; j < set_size3; j++)
        {

            pod_matrix1_set3[i][j] = k;
            // cout << "k = " << k;
            k++;
        }
    }
    cout << "Matrix 1 Set 3:\n"
         << endl;

    print_partial_matrix(pod_matrix1_set3, set_size3);

    // Second Matrix
    vector<vector<double>> pod_matrix2_set3(set_size3, vector<double>(set_size3));
    k = 0.0;
    for (unsigned int i = 0; i < set_size3; i++)
    {
        for (unsigned int j = 0; j < set_size3; j++)
        {
            pod_matrix2_set3[i][j] = static_cast<double>((int(k) % 2) + 1);
            k++;
        }
    }
    cout << "Matrix 2 Set 3:\n"
         << endl;

    print_partial_matrix(pod_matrix2_set3, set_size3);

    // Encode the matrices
    vector<Plaintext> plain_matrix1_set1(set_size1), plain_matrix2_set1(set_size1);
    vector<Plaintext> plain_matrix1_set2(set_size2), plain_matrix2_set2(set_size2);
    vector<Plaintext> plain_matrix1_set3(set_size3), plain_matrix2_set3(set_size3);

    double scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));

    // First set encode
    for (unsigned int i = 0; i < pod_matrix1_set1.size(); i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    for (unsigned int i = 0; i < pod_matrix2_set1.size(); i++)
    {
        ckks_encoder.encode(pod_matrix2_set1[i], scale, plain_matrix2_set1[i]);
    }

    // Second set encode
    for (unsigned int i = 0; i < pod_matrix1_set2.size(); i++)
    {
        ckks_encoder.encode(pod_matrix1_set2[i], scale, plain_matrix1_set2[i]);
    }
    for (unsigned int i = 0; i < pod_matrix2_set2.size(); i++)
    {
        ckks_encoder.encode(pod_matrix2_set2[i], scale, plain_matrix2_set2[i]);
    }

    // Third set encode
    for (unsigned int i = 0; i < pod_matrix1_set3.size(); i++)
    {
        ckks_encoder.encode(pod_matrix1_set3[i], scale, plain_matrix1_set3[i]);
    }
    for (unsigned int i = 0; i < pod_matrix2_set3.size(); i++)
    {
        ckks_encoder.encode(pod_matrix2_set3[i], scale, plain_matrix2_set3[i]);
    }

    // Encrypt the matrices
    vector<Ciphertext> cipher_matrix1_set1(set_size1), cipher_matrix2_set1(set_size1);
    vector<Ciphertext> cipher_matrix1_set2(set_size2), cipher_matrix2_set2(set_size2);
    vector<Ciphertext> cipher_matrix1_set3(set_size3), cipher_matrix2_set3(set_size3);

    // First set cipher
    for (unsigned int i = 0; i < plain_matrix1_set1.size(); i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
    }
    for (unsigned int i = 0; i < plain_matrix2_set1.size(); i++)
    {
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
    }

    // Second set cipher
    for (unsigned int i = 0; i < plain_matrix1_set2.size(); i++)
    {
        encryptor.encrypt(plain_matrix1_set2[i], cipher_matrix1_set2[i]);
    }
    for (unsigned int i = 0; i < plain_matrix2_set2.size(); i++)
    {
        encryptor.encrypt(plain_matrix2_set2[i], cipher_matrix2_set2[i]);
    }

    // Third set cipher
    for (unsigned int i = 0; i < plain_matrix1_set3.size(); i++)
    {
        encryptor.encrypt(plain_matrix1_set3[i], cipher_matrix1_set3[i]);
    }
    for (unsigned int i = 0; i < plain_matrix2_set3.size(); i++)
    {
        encryptor.encrypt(plain_matrix2_set3[i], cipher_matrix2_set3[i]);
    }

    // Create ciphertext output
    // Set 1 output
    vector<Ciphertext> cipher_result1_set1(set_size1), cipher_result2_set1(set_size1), cipher_result3_set1(set_size1), cipher_result4_set1(set_size1);
    // Set 2 output
    vector<Ciphertext> cipher_result1_set2(set_size2), cipher_result2_set2(set_size2), cipher_result3_set2(set_size2), cipher_result4_set2(set_size2);
    // Set 3 output
    vector<Ciphertext> cipher_result1_set3(set_size3), cipher_result2_set3(set_size3), cipher_result3_set3(set_size3), cipher_result4_set3(set_size3);

    // ------------------ (cipher1 + plain2) ---------------
    cout << "\n------------------ FIRST OPERATION ------------------\n"
         << endl;
    outf << "# index 0" << endl;
    outf << "# C1 + P2" << endl;

    // Compute (cipher1 + plain2) for set 1
    cout << "Compute (cipher1 + plain2) for set 1" << endl;

    // TIME START
    auto start_comp1_set1 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set1.size(); i++)
    {
        evaluator.add_plain(cipher_matrix1_set1[i], plain_matrix2_set1[i], cipher_result1_set1[i]);
    }

    // TIME END
    auto stop_comp1_set1 = chrono::high_resolution_clock::now();
    auto duration_comp1_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set1 - start_comp1_set1);

    // Decrypt and Decode
    vector<Plaintext> plain_result1_set1(set_size1);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result1_set1.size(); i++)
    {
        decryptor.decrypt(cipher_result1_set1[i], plain_result1_set1[i]);
    }
    vector<vector<double>> matrix_result1_set1(set_size1, vector<double>(set_size1));
    for (unsigned int i = 0; i < plain_result1_set1.size(); i++)
    {
        ckks_encoder.decode(plain_result1_set1[i], matrix_result1_set1[i]);
    }

    print_partial_matrix(matrix_result1_set1, set_size1);

    cout << "\nTime to compute cipher1 + plain2: " << duration_comp1_set1.count() << " microseconds" << endl;
    outf << set_size1 << "\t\t" << duration_comp1_set1.count() << endl;

    // Compute (cipher1 + plain2) for set 2
    cout << "Compute (cipher1 + plain2) for set 2" << endl;

    // TIME START
    auto start_comp1_set2 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set2.size(); i++)
    {
        evaluator.add_plain(cipher_matrix1_set2[i], plain_matrix2_set2[i], cipher_result1_set2[i]);
    }

    // TIME END
    auto stop_comp1_set2 = chrono::high_resolution_clock::now();
    auto duration_comp1_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set2 - start_comp1_set2);

    // Decrypt and Decode
    vector<Plaintext> plain_result1_set2(set_size2);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result1_set2.size(); i++)
    {
        decryptor.decrypt(cipher_result1_set2[i], plain_result1_set2[i]);
    }
    vector<vector<double>> matrix_result1_set2(set_size2, vector<double>(set_size2));
    for (unsigned int i = 0; i < plain_result1_set2.size(); i++)
    {
        ckks_encoder.decode(plain_result1_set2[i], matrix_result1_set2[i]);
    }

    print_partial_matrix(matrix_result1_set2, set_size2);

    cout << "\nTime to compute cipher1 + plain2: " << duration_comp1_set2.count() << " microseconds" << endl;
    outf << set_size2 << "\t\t" << duration_comp1_set2.count() << endl;

    // Compute (cipher1 + plain2) for set 3
    cout << "Compute (cipher1 + plain2) for set 3" << endl;

    // TIME START
    auto start_comp1_set3 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set3.size(); i++)
    {
        evaluator.add_plain(cipher_matrix1_set3[i], plain_matrix2_set3[i], cipher_result1_set3[i]);
    }

    // TIME END
    auto stop_comp1_set3 = chrono::high_resolution_clock::now();
    auto duration_comp1_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp1_set3 - start_comp1_set3);

    // Decrypt and Decode
    vector<Plaintext> plain_result1_set3(set_size3);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result1_set3.size(); i++)
    {
        decryptor.decrypt(cipher_result1_set3[i], plain_result1_set3[i]);
    }
    vector<vector<double>> matrix_result1_set3(set_size3, vector<double>(set_size3));
    for (unsigned int i = 0; i < plain_result1_set3.size(); i++)
    {
        ckks_encoder.decode(plain_result1_set3[i], matrix_result1_set3[i]);
    }

    print_partial_matrix(matrix_result1_set3, set_size3);

    cout << "\nTime to compute cipher1 + plain2: " << duration_comp1_set3.count() << " microseconds" << endl;
    outf << set_size3 << "\t\t" << duration_comp1_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;
    // ------------------ (cipher1 + cipher2) ---------------
    cout << "\n------------------ SECOND OPERATION ------------------\n"
         << endl;
    outf << "# index 1" << endl;
    outf << "# C1 + C2" << endl;

    // Compute (cipher1 + cipher2) for set 1
    cout << "Compute (cipher1 + cipher2) for set 1" << endl;

    // TIME START
    auto start_comp2_set1 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set1.size(); i++)
    {
        evaluator.add(cipher_matrix1_set1[i], cipher_matrix2_set1[i], cipher_result2_set1[i]);
    }

    // TIME END
    auto stop_comp2_set1 = chrono::high_resolution_clock::now();
    auto duration_comp2_set1 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set1 - start_comp2_set1);

    // Decrypt and Decode
    vector<Plaintext> plain_result2_set1(set_size1);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result2_set1.size(); i++)
    {
        decryptor.decrypt(cipher_result2_set1[i], plain_result2_set1[i]);
    }
    vector<vector<double>> matrix_result2_set1(set_size1, vector<double>(set_size1));
    for (unsigned int i = 0; i < plain_result2_set1.size(); i++)
    {
        ckks_encoder.decode(plain_result2_set1[i], matrix_result2_set1[i]);
    }

    print_partial_matrix(matrix_result2_set1, set_size1);

    cout << "\nTime to compute cipher1 + cipher2: " << duration_comp2_set1.count() << " microseconds" << endl;
    outf << set_size1 << "\t\t" << duration_comp2_set1.count() << endl;

    // Compute (cipher1 + cipher2) for set 2
    cout << "Compute (cipher1 + cipher2) for set 2" << endl;

    // TIME START
    auto start_comp2_set2 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set2.size(); i++)
    {
        evaluator.add(cipher_matrix1_set2[i], cipher_matrix2_set2[i], cipher_result2_set2[i]);
    }

    // TIME END
    auto stop_comp2_set2 = chrono::high_resolution_clock::now();
    auto duration_comp2_set2 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set2 - start_comp2_set2);

    // Decrypt and Decode
    vector<Plaintext> plain_result2_set2(set_size2);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result2_set2.size(); i++)
    {
        decryptor.decrypt(cipher_result2_set2[i], plain_result2_set2[i]);
    }
    vector<vector<double>> matrix_result2_set2(set_size2, vector<double>(set_size2));
    for (unsigned int i = 0; i < plain_result2_set2.size(); i++)
    {
        ckks_encoder.decode(plain_result2_set2[i], matrix_result2_set2[i]);
    }

    print_partial_matrix(matrix_result2_set2, set_size2);

    cout << "\nTime to compute cipher1 + cipher2: " << duration_comp2_set2.count() << " microseconds" << endl;
    outf << set_size2 << "\t\t" << duration_comp2_set2.count() << endl;

    // Compute (cipher1 + cipher2) for set 3
    cout << "Compute (cipher1 + cipher2) for set 3" << endl;

    // TIME START
    auto start_comp2_set3 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < cipher_matrix1_set3.size(); i++)
    {
        evaluator.add(cipher_matrix1_set3[i], cipher_matrix2_set3[i], cipher_result2_set3[i]);
    }

    // TIME END
    auto stop_comp2_set3 = chrono::high_resolution_clock::now();
    auto duration_comp2_set3 = chrono::duration_cast<chrono::microseconds>(stop_comp2_set3 - start_comp2_set3);

    // Decrypt and Decode
    vector<Plaintext> plain_result2_set3(set_size3);
    cout << "Decrypt and decode the result" << endl;
    for (unsigned int i = 0; i < cipher_result2_set3.size(); i++)
    {
        decryptor.decrypt(cipher_result2_set3[i], plain_result2_set3[i]);
    }
    vector<vector<double>> matrix_result2_set3(set_size3, vector<double>(set_size3));
    for (unsigned int i = 0; i < plain_result2_set3.size(); i++)
    {
        ckks_encoder.decode(plain_result2_set3[i], matrix_result2_set3[i]);
    }

    print_partial_matrix(matrix_result2_set3, set_size3);

    cout << "\nTime to compute cipher1 + cipher2: " << duration_comp2_set3.count() << " microseconds" << endl;
    outf << set_size3 << "\t\t" << duration_comp2_set3.count() << endl;

    outf.close();
}

int main()
{

    // Need to plot graph with x-axis as the size and y-axis as the duration
    // Plot 3 different graphs (with 3 different ploy_modulus_degree)
    EncryptionParameters params(scheme_type::CKKS);

    // Case 1 : poly_modulus_degree = 4096
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Run the tests
    ckksBenchmark(poly_modulus_degree);
    ckksBenchmarkMatrix(poly_modulus_degree);

    return 0;
}
