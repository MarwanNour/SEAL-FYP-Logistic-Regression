#include <iostream>
#include <iomanip>
#include <fstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

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

void slowEncoding(size_t poly_modulus_degree)
{
    // Set output file
    string filename = "matrix_ops_" + to_string(poly_modulus_degree) + ".dat";
    ofstream outf(filename);

    // Handle file error
    if (!outf)
    {
        cerr << "Couldn't open file: " << filename << endl;
        exit(1);
    }

    // Set output script
    string script = "script_matrix_ops_" + to_string(poly_modulus_degree) + ".p";
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
    outscript << "set output \"canvas_matrix_ops_" << to_string(poly_modulus_degree) << ".html\"" << endl;
    outscript << "set title \"CKKS Matrix Ops Benchmark " << to_string(poly_modulus_degree) << "\"" << endl;
    outscript << "set xlabel 'Input Vector Size'" << endl;
    outscript << "set ylabel 'Time (microseconds)'" << endl;

    outscript << "\n# Set the styling " << endl;
    outscript << "set style line 1\\\n"
              << "linecolor rgb '#3da3f5'\\\n"
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

    outscript << "set style line 5\\\n"
              << "linecolor rgb '#f5a142'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 3 pointsize 1.5\n"
              << endl;

    outscript << "set style line 6\\\n"
              << "linecolor rgb '#07025e'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 2 pointsize 1.5\n"
              << endl;

    outscript << "set style line 7\\\n"
              << "linecolor rgb '#07025e'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 9 pointsize 1.5\n"
              << endl;

    outscript << "set style line 8\\\n"
              << "linecolor rgb '#07025e'\\\n"
              << "linetype 1 linewidth 2\\\n"
              << "pointtype 10 pointsize 1.5\n"
              << endl;

    outscript << "\nplot 'matrix_ops_" << to_string(poly_modulus_degree) << ".dat'"
              << " index 0 title \"Encoding\"  with linespoints ls 1, \\\n"
              << "'' index 1 title \"Encrypting\"  with linespoints ls 2, \\\n"
              << "'' index 2 title \"C1 + P2\" with linespoints ls 3, \\\n"
              << "'' index 3 title \"C1 + C2\"  with linespoints ls 4, \\\n"
              << "'' index 4 title \"C1 * P2\"  with linespoints ls 5, \\\n"
              << "'' index 5 title \"C1 * C2\"  with linespoints ls 6, \\\n"
              << "'' index 6 title \"C1 . P2\"  with linespoints ls 7, \\\n"
              << "'' index 7 title \"C1 . C2\"  with linespoints ls 8";

    // Close script
    outscript.close();

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
    // Create scale
    double scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));

    int dimension1 = 10;
    cout << "Dimension Set 1 :" << dimension1 << endl
         << endl;

    int dimension2 = 100;
    cout << "Dimension Set 2 :" << dimension2 << endl
         << endl;

    int dimension3 = 300;
    cout << "Dimension Set 3 :" << dimension3 << endl
         << endl;

    // Create Input matrices
    // Set 1
    vector<vector<double>> pod_matrix1_set1(dimension1, vector<double>(dimension1));
    vector<vector<double>> pod_matrix2_set1(dimension1, vector<double>(dimension1));
    // Set 2
    vector<vector<double>> pod_matrix1_set2(dimension2, vector<double>(dimension2));
    vector<vector<double>> pod_matrix2_set2(dimension2, vector<double>(dimension2));
    // Set 3
    vector<vector<double>> pod_matrix1_set3(dimension3, vector<double>(dimension3));
    vector<vector<double>> pod_matrix2_set3(dimension3, vector<double>(dimension3));

    // Fill input matrices
    double filler = 0.0;
    // Set 1
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            pod_matrix1_set1[i][j] = filler;
            pod_matrix2_set1[i][j] = static_cast<double>((j % 2) + 1);
            filler++;
        }
    }
    print_partial_matrix(pod_matrix1_set1);
    print_partial_matrix(pod_matrix2_set1);

    // Set 2
    filler = 0.0;
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            pod_matrix1_set2[i][j] = filler;
            pod_matrix2_set2[i][j] = static_cast<double>((j % 2) + 1);
            filler++;
        }
    }

    // Set 3
    filler = 0.0;
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            pod_matrix1_set3[i][j] = filler;
            pod_matrix2_set3[i][j] = static_cast<double>((j % 2) + 1);
            filler++;
        }
    }

    // Encode matrices
    // Set 1
    vector<vector<Plaintext>> plain_matrix1_set1(dimension1, vector<Plaintext>(dimension1));
    vector<vector<Plaintext>> plain_matrix2_set1(dimension1, vector<Plaintext>(dimension1));
    // Set 2
    vector<vector<Plaintext>> plain_matrix1_set2(dimension2, vector<Plaintext>(dimension2));
    vector<vector<Plaintext>> plain_matrix2_set2(dimension2, vector<Plaintext>(dimension2));
    // Set 1
    vector<vector<Plaintext>> plain_matrix1_set3(dimension3, vector<Plaintext>(dimension3));
    vector<vector<Plaintext>> plain_matrix2_set3(dimension3, vector<Plaintext>(dimension3));

    outf << "# index 0" << endl;
    outf << "# Encoding" << endl;
    // Set 1
    auto start_encode_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            ckks_encoder.encode(pod_matrix1_set1[i][j], scale, plain_matrix1_set1[i][j]);
            ckks_encoder.encode(pod_matrix2_set1[i][j], scale, plain_matrix2_set1[i][j]);
        }
    }

    auto stop_encode_set1 = chrono::high_resolution_clock::now();
    auto duration_encode_set1 = chrono::duration_cast<chrono::microseconds>(stop_encode_set1 - start_encode_set1);

    cout << "Encoding time Set 1: " << duration_encode_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_encode_set1.count() << endl;

    // Set 2
    auto start_encode_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            ckks_encoder.encode(pod_matrix1_set2[i][j], scale, plain_matrix1_set2[i][j]);
            ckks_encoder.encode(pod_matrix2_set2[i][j], scale, plain_matrix2_set2[i][j]);
        }
    }

    auto stop_encode_set2 = chrono::high_resolution_clock::now();
    auto duration_encode_set2 = chrono::duration_cast<chrono::microseconds>(stop_encode_set2 - start_encode_set2);

    cout << "Encoding time Set 2: " << duration_encode_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_encode_set2.count() << endl;

    // Set 3
    auto start_encode_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            ckks_encoder.encode(pod_matrix1_set3[i][j], scale, plain_matrix1_set3[i][j]);
            ckks_encoder.encode(pod_matrix2_set3[i][j], scale, plain_matrix2_set3[i][j]);
        }
    }

    auto stop_encode_set3 = chrono::high_resolution_clock::now();
    auto duration_encode_set3 = chrono::duration_cast<chrono::microseconds>(stop_encode_set3 - start_encode_set3);

    cout << "Encoding time Set 3: " << duration_encode_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_encode_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // Encrypt the matrices
    // Set 1
    vector<vector<Ciphertext>> cipher_matrix1_set1(dimension1, vector<Ciphertext>(dimension1));
    vector<vector<Ciphertext>> cipher_matrix2_set1(dimension1, vector<Ciphertext>(dimension1));
    // Set 2
    vector<vector<Ciphertext>> cipher_matrix1_set2(dimension2, vector<Ciphertext>(dimension2));
    vector<vector<Ciphertext>> cipher_matrix2_set2(dimension2, vector<Ciphertext>(dimension2));
    // Set 3
    vector<vector<Ciphertext>> cipher_matrix1_set3(dimension3, vector<Ciphertext>(dimension3));
    vector<vector<Ciphertext>> cipher_matrix2_set3(dimension3, vector<Ciphertext>(dimension3));

    outf << "# index 1" << endl;
    outf << "# Encryption" << endl;

    // Set 1
    auto start_encrypt_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            encryptor.encrypt(plain_matrix1_set1[i][j], cipher_matrix1_set1[i][j]);
            encryptor.encrypt(plain_matrix2_set1[i][j], cipher_matrix2_set1[i][j]);
        }
    }
    auto stop_encrypt_set1 = chrono::high_resolution_clock::now();
    auto duration_encrypt_set1 = chrono::duration_cast<chrono::microseconds>(stop_encrypt_set1 - start_encrypt_set1);

    cout << "Encryption time Set 1: " << duration_encrypt_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_encrypt_set1.count() << endl;

    // Set 2
    auto start_encrypt_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            encryptor.encrypt(plain_matrix1_set2[i][j], cipher_matrix1_set2[i][j]);
            encryptor.encrypt(plain_matrix2_set2[i][j], cipher_matrix2_set2[i][j]);
        }
    }
    auto stop_encrypt_set2 = chrono::high_resolution_clock::now();
    auto duration_encrypt_set2 = chrono::duration_cast<chrono::microseconds>(stop_encrypt_set2 - start_encrypt_set2);

    cout << "Encryption time Set 2: " << duration_encrypt_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_encrypt_set2.count() << endl;

    // Set 3
    auto start_encrypt_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            encryptor.encrypt(plain_matrix1_set3[i][j], cipher_matrix1_set3[i][j]);
            encryptor.encrypt(plain_matrix2_set3[i][j], cipher_matrix2_set3[i][j]);
        }
    }
    auto stop_encrypt_set3 = chrono::high_resolution_clock::now();
    auto duration_encrypt_set3 = chrono::duration_cast<chrono::microseconds>(stop_encrypt_set3 - start_encrypt_set3);

    cout << "Encryption time Set 3: " << duration_encrypt_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_encrypt_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1+P2
    cout << "\n----------------- C1 + P2----------------\n"
         << endl;
    outf << "# index 2" << endl;
    outf << "# C1 + P2" << endl;

    // Set 1
    vector<vector<Ciphertext>> cipher_result_addition_plain_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_add_plain_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            evaluator.add_plain(cipher_matrix1_set1[i][j], plain_matrix2_set1[i][j], cipher_result_addition_plain_set1[i][j]);
        }
    }

    auto stop_add_plain_set1 = chrono::high_resolution_clock::now();
    auto duration_add_plain_set1 = chrono::duration_cast<chrono::microseconds>(stop_add_plain_set1 - start_add_plain_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_plain_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set1[i][j], plain_result_addition_plain_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_plain_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_plain_set1[i][j], temp);
            pod_result_addition_plain_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_plain_set1);

    cout << "Compute C1+P2 time Set 1: " << duration_add_plain_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_add_plain_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_addition_plain_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_add_plain_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            evaluator.add_plain(cipher_matrix1_set2[i][j], plain_matrix2_set2[i][j], cipher_result_addition_plain_set2[i][j]);
        }
    }

    auto stop_add_plain_set2 = chrono::high_resolution_clock::now();
    auto duration_add_plain_set2 = chrono::duration_cast<chrono::microseconds>(stop_add_plain_set2 - start_add_plain_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_plain_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set2[i][j], plain_result_addition_plain_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_plain_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_plain_set2[i][j], temp);
            pod_result_addition_plain_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_plain_set2);

    cout << "Compute C1+P2 time Set 2: " << duration_add_plain_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_add_plain_set2.count() << endl;

    // Set 3
    vector<vector<Ciphertext>> cipher_result_addition_plain_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_add_plain_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            evaluator.add_plain(cipher_matrix1_set3[i][j], plain_matrix2_set3[i][j], cipher_result_addition_plain_set3[i][j]);
        }
    }

    auto stop_add_plain_set3 = chrono::high_resolution_clock::now();
    auto duration_add_plain_set3 = chrono::duration_cast<chrono::microseconds>(stop_add_plain_set3 - start_add_plain_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_plain_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set3[i][j], plain_result_addition_plain_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_plain_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_plain_set3[i][j], temp);
            pod_result_addition_plain_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_plain_set3);

    cout << "Compute C1+P2 time Set 3: " << duration_add_plain_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_add_plain_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1+C2
    cout << "\n----------------- C1 + C2----------------\n"
         << endl;

    outf << "# index 3" << endl;
    outf << "# C1 + C2";

    // Set 1
    vector<vector<Ciphertext>> cipher_result_addition_cipher_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_add_cipher_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            evaluator.add(cipher_matrix1_set1[i][j], cipher_matrix2_set1[i][j], cipher_result_addition_cipher_set1[i][j]);
        }
    }

    auto stop_add_cipher_set1 = chrono::high_resolution_clock::now();
    auto duration_add_cipher_set1 = chrono::duration_cast<chrono::microseconds>(stop_add_cipher_set1 - start_add_cipher_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_cipher_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set1[i][j], plain_result_addition_cipher_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_cipher_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_cipher_set1[i][j], temp);
            pod_result_addition_cipher_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_cipher_set1);

    cout << "Compute C1+C2 time Set 1: " << duration_add_cipher_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_add_cipher_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_addition_cipher_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_add_cipher_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            evaluator.add(cipher_matrix1_set2[i][j], cipher_matrix2_set2[i][j], cipher_result_addition_cipher_set2[i][j]);
        }
    }

    auto stop_add_cipher_set2 = chrono::high_resolution_clock::now();
    auto duration_add_cipher_set2 = chrono::duration_cast<chrono::microseconds>(stop_add_cipher_set2 - start_add_cipher_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_cipher_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set2[i][j], plain_result_addition_cipher_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_cipher_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_cipher_set2[i][j], temp);
            pod_result_addition_cipher_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_cipher_set2);

    cout << "Compute C1+C2 time Set 2: " << duration_add_cipher_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_add_cipher_set2.count() << endl;

    // Set 3
    vector<vector<Ciphertext>> cipher_result_addition_cipher_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_add_cipher_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            evaluator.add(cipher_matrix1_set3[i][j], cipher_matrix2_set3[i][j], cipher_result_addition_cipher_set3[i][j]);
        }
    }

    auto stop_add_cipher_set3 = chrono::high_resolution_clock::now();
    auto duration_add_cipher_set3 = chrono::duration_cast<chrono::microseconds>(stop_add_cipher_set3 - start_add_cipher_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_addition_cipher_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_addition_plain_set3[i][j], plain_result_addition_cipher_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_addition_cipher_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_addition_cipher_set3[i][j], temp);
            pod_result_addition_cipher_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_addition_cipher_set3);

    cout << "Compute C1+C2 time Set 3: " << duration_add_cipher_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_add_cipher_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1*P2
    cout << "\n----------------- C1 * P2 (component-wise)----------------\n"
         << endl;

    outf << "# index 4" << endl;
    outf << "# C1 * P2" << endl;

    // Set 1
    vector<vector<Ciphertext>> cipher_result_mult_plain_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_mult_plain_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            evaluator.multiply_plain(cipher_matrix1_set1[i][j], plain_matrix2_set1[i][j], cipher_result_mult_plain_set1[i][j]);
        }
    }

    auto stop_mult_plain_set1 = chrono::high_resolution_clock::now();
    auto duration_mult_plain_set1 = chrono::duration_cast<chrono::microseconds>(stop_mult_plain_set1 - start_mult_plain_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_plain_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_mult_plain_set1[i][j], plain_result_mult_plain_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_plain_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_plain_set1[i][j], temp);
            pod_result_mult_plain_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_plain_set1);

    cout << "Compute C1 * P2 (component-wise) time Set 1: " << duration_mult_plain_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_mult_plain_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_mult_plain_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_mult_plain_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            evaluator.multiply_plain(cipher_matrix1_set2[i][j], plain_matrix2_set2[i][j], cipher_result_mult_plain_set2[i][j]);
        }
    }

    auto stop_mult_plain_set2 = chrono::high_resolution_clock::now();
    auto duration_mult_plain_set2 = chrono::duration_cast<chrono::microseconds>(stop_mult_plain_set2 - start_mult_plain_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_plain_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_mult_plain_set2[i][j], plain_result_mult_plain_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_plain_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_plain_set2[i][j], temp);
            pod_result_mult_plain_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_plain_set2);

    cout << "Compute C1 * P2 (component-wise) time Set 2: " << duration_mult_plain_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_mult_plain_set2.count() << endl;

    // Set 3
    vector<vector<Ciphertext>> cipher_result_mult_plain_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_mult_plain_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            evaluator.multiply_plain(cipher_matrix1_set3[i][j], plain_matrix2_set3[i][j], cipher_result_mult_plain_set3[i][j]);
        }
    }

    auto stop_mult_plain_set3 = chrono::high_resolution_clock::now();
    auto duration_mult_plain_set3 = chrono::duration_cast<chrono::microseconds>(stop_mult_plain_set3 - start_mult_plain_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_plain_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_mult_plain_set3[i][j], plain_result_mult_plain_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_plain_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_plain_set3[i][j], temp);
            pod_result_mult_plain_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_plain_set3);

    cout << "Compute C1 * P2 (component-wise) time Set 3: " << duration_mult_plain_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_mult_plain_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1*C2
    cout << "\n----------------- C1 * C2 (component-wise)----------------\n"
         << endl;

    outf << "# index 5" << endl;
    outf << "# C1 * C2" << endl;

    // Set 1
    vector<vector<Ciphertext>> cipher_result_mult_cipher_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_mult_cipher_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            evaluator.multiply(cipher_matrix1_set1[i][j], cipher_matrix2_set1[i][j], cipher_result_mult_cipher_set1[i][j]);
        }
    }

    auto stop_mult_cipher_set1 = chrono::high_resolution_clock::now();
    auto duration_mult_cipher_set1 = chrono::duration_cast<chrono::microseconds>(stop_mult_cipher_set1 - start_mult_cipher_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_cipher_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_mult_cipher_set1[i][j], plain_result_mult_cipher_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_cipher_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_cipher_set1[i][j], temp);
            pod_result_mult_cipher_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_cipher_set1);

    cout << "Compute C1 * C2 (component-wise) time Set 1: " << duration_mult_cipher_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_mult_cipher_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_mult_cipher_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_mult_cipher_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            evaluator.multiply(cipher_matrix1_set2[i][j], cipher_matrix2_set2[i][j], cipher_result_mult_cipher_set2[i][j]);
        }
    }

    auto stop_mult_cipher_set2 = chrono::high_resolution_clock::now();
    auto duration_mult_cipher_set2 = chrono::duration_cast<chrono::microseconds>(stop_mult_cipher_set2 - start_mult_cipher_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_cipher_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_mult_cipher_set2[i][j], plain_result_mult_cipher_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_cipher_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_cipher_set2[i][j], temp);
            pod_result_mult_cipher_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_cipher_set2);

    cout << "Compute C1 * C2 (component-wise) time Set 2: " << duration_mult_cipher_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_mult_cipher_set2.count() << endl;

    // Set 3
    vector<vector<Ciphertext>> cipher_result_mult_cipher_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_mult_cipher_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            evaluator.multiply(cipher_matrix1_set3[i][j], cipher_matrix2_set3[i][j], cipher_result_mult_cipher_set3[i][j]);
        }
    }

    auto stop_mult_cipher_set3 = chrono::high_resolution_clock::now();
    auto duration_mult_cipher_set3 = chrono::duration_cast<chrono::microseconds>(stop_mult_cipher_set3 - start_mult_cipher_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_mult_cipher_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_mult_cipher_set3[i][j], plain_result_mult_cipher_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_mult_cipher_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_mult_cipher_set3[i][j], temp);
            pod_result_mult_cipher_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_mult_cipher_set3);

    cout << "Compute C1 * C2 (component-wise) time Set 3: " << duration_mult_cipher_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_mult_cipher_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1*P2 (Matrix)
    cout << "\n----------------- C1 * P2 (matrix multiplication)----------------\n"
         << endl;

    outf << "# index 6" << endl;
    outf << "# C1 . C2" << endl;

    // Set 1
    vector<vector<Ciphertext>> cipher_result_matrix_mult_plain_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_matrix_mult_plain_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<Ciphertext> temp(dimension1);
            for (int k = 0; k < dimension1; k++)
            {
                evaluator.multiply_plain(cipher_matrix1_set1[i][k], plain_matrix2_set1[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_plain_set1[i][j]);
        }
    }

    auto stop_matrix_mult_plain_set1 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_plain_set1 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_plain_set1 - start_matrix_mult_plain_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_plain_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_plain_set1[i][j], plain_result_matrix_mult_plain_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_plain_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_plain_set1[i][j], temp);
            pod_result_matrix_mult_plain_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_plain_set1);

    cout << "Compute C1 * P2 (matrix multiplication) time  Set 1: " << duration_matrix_mult_plain_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_matrix_mult_plain_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_matrix_mult_plain_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_matrix_mult_plain_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<Ciphertext> temp(dimension2);
            for (int k = 0; k < dimension2; k++)
            {
                evaluator.multiply_plain(cipher_matrix1_set2[i][k], plain_matrix2_set2[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_plain_set2[i][j]);
        }
    }

    auto stop_matrix_mult_plain_set2 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_plain_set2 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_plain_set2 - start_matrix_mult_plain_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_plain_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_plain_set2[i][j], plain_result_matrix_mult_plain_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_plain_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_plain_set2[i][j], temp);
            pod_result_matrix_mult_plain_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_plain_set2);

    cout << "Compute C1 * P2 (matrix multiplication) time  Set 2: " << duration_matrix_mult_plain_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_matrix_mult_plain_set2.count() << endl;

    // Set 3
    vector<vector<Ciphertext>> cipher_result_matrix_mult_plain_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_matrix_mult_plain_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<Ciphertext> temp(dimension3);
            for (int k = 0; k < dimension3; k++)
            {
                evaluator.multiply_plain(cipher_matrix1_set3[i][k], plain_matrix2_set3[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_plain_set3[i][j]);
        }
    }

    auto stop_matrix_mult_plain_set3 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_plain_set3 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_plain_set3 - start_matrix_mult_plain_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_plain_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_plain_set3[i][j], plain_result_matrix_mult_plain_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_plain_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_plain_set3[i][j], temp);
            pod_result_matrix_mult_plain_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_plain_set3);

    cout << "Compute C1 * P2 (matrix multiplication) time  Set 3: " << duration_matrix_mult_plain_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_matrix_mult_plain_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;

    // C1*C2 (Matrix)
    cout << "\n----------------- C1 * C2 (matrix multiplication)----------------\n"
         << endl;

    outf << "# index 7" << endl;
    outf << "# C1 . C2" << endl;

    // Set 1
    vector<vector<Ciphertext>> cipher_result_matrix_mult_cipher_set1(dimension1, vector<Ciphertext>(dimension1));

    auto start_matrix_mult_cipher_set1 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<Ciphertext> temp(dimension1);
            for (int k = 0; k < dimension1; k++)
            {
                evaluator.multiply(cipher_matrix1_set1[i][k], cipher_matrix2_set1[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_cipher_set1[i][j]);
        }
    }

    auto stop_matrix_mult_cipher_set1 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_cipher_set1 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_cipher_set1 - start_matrix_mult_cipher_set1);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_cipher_set1(dimension1, vector<Plaintext>(dimension1));

    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_cipher_set1[i][j], plain_result_matrix_mult_cipher_set1[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_cipher_set1(dimension1, vector<double>(dimension1));
    for (int i = 0; i < dimension1; i++)
    {
        for (int j = 0; j < dimension1; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_cipher_set1[i][j], temp);
            pod_result_matrix_mult_cipher_set1[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_cipher_set1);

    cout << "Compute C1 * C2 (matrix multiplication) time  Set 1: " << duration_matrix_mult_cipher_set1.count() << " microseconds" << endl;
    outf << dimension1 << "\t\t" << duration_matrix_mult_cipher_set1.count() << endl;

    // Set 2
    vector<vector<Ciphertext>> cipher_result_matrix_mult_cipher_set2(dimension2, vector<Ciphertext>(dimension2));

    auto start_matrix_mult_cipher_set2 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<Ciphertext> temp(dimension2);
            for (int k = 0; k < dimension2; k++)
            {
                evaluator.multiply(cipher_matrix1_set2[i][k], cipher_matrix2_set2[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_cipher_set2[i][j]);
        }
    }

    auto stop_matrix_mult_cipher_set2 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_cipher_set2 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_cipher_set2 - start_matrix_mult_cipher_set2);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_cipher_set2(dimension2, vector<Plaintext>(dimension2));

    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_cipher_set2[i][j], plain_result_matrix_mult_cipher_set2[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_cipher_set2(dimension2, vector<double>(dimension2));
    for (int i = 0; i < dimension2; i++)
    {
        for (int j = 0; j < dimension2; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_cipher_set2[i][j], temp);
            pod_result_matrix_mult_cipher_set2[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_cipher_set2);

    cout << "Compute C1 * C2 (matrix multiplication) time  Set 2: " << duration_matrix_mult_cipher_set2.count() << " microseconds" << endl;
    outf << dimension2 << "\t\t" << duration_matrix_mult_cipher_set2.count() << endl;
    

    // Set 3
    vector<vector<Ciphertext>> cipher_result_matrix_mult_cipher_set3(dimension3, vector<Ciphertext>(dimension3));

    auto start_matrix_mult_cipher_set3 = chrono::high_resolution_clock::now();

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<Ciphertext> temp(dimension3);
            for (int k = 0; k < dimension3; k++)
            {
                evaluator.multiply(cipher_matrix1_set3[i][k], cipher_matrix2_set3[k][j], temp[k]);
            }
            evaluator.add_many(temp, cipher_result_matrix_mult_cipher_set3[i][j]);
        }
    }

    auto stop_matrix_mult_cipher_set3 = chrono::high_resolution_clock::now();
    auto duration_matrix_mult_cipher_set3 = chrono::duration_cast<chrono::microseconds>(stop_matrix_mult_cipher_set3 - start_matrix_mult_cipher_set3);

    // Decrypt
    vector<vector<Plaintext>> plain_result_matrix_mult_cipher_set3(dimension3, vector<Plaintext>(dimension3));

    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            decryptor.decrypt(cipher_result_matrix_mult_cipher_set3[i][j], plain_result_matrix_mult_cipher_set3[i][j]);
        }
    }

    // Decode
    vector<vector<double>> pod_result_matrix_mult_cipher_set3(dimension3, vector<double>(dimension3));
    for (int i = 0; i < dimension3; i++)
    {
        for (int j = 0; j < dimension3; j++)
        {
            vector<double> temp;
            ckks_encoder.decode(plain_result_matrix_mult_cipher_set3[i][j], temp);
            pod_result_matrix_mult_cipher_set3[i][j] = temp[0];
        }
    }
    // Print output
    print_partial_matrix(pod_result_matrix_mult_cipher_set3);

    cout << "Compute C1 * C2 (matrix multiplication) time  Set 3: " << duration_matrix_mult_cipher_set3.count() << " microseconds" << endl;
    outf << dimension3 << "\t\t" << duration_matrix_mult_cipher_set3.count() << endl;

    cout << endl;
    outf << "\n"
         << endl;
         
    outf.close();
}

int main()
{
    slowEncoding(4096);

    return 0;
}