#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>

using namespace std;

float vector_dot_product(vector<float> vec_A, vector<float> vec_B)
{
    if (vec_A.size() != vec_B.size())
    {
        cerr << "Vector size mismatch" << endl;
        exit(EXIT_FAILURE);
    }
    float result = 0;
    for (unsigned int i = 0; i < vec_A.size(); i++)
    {
        result += vec_A[i] * vec_B[i];
    }

    return result;
}

vector<float> linear_transformation(vector<vector<float>> input_matrix, vector<float> input_vec)
{
    vector<float> result_vec(input_vec.size());
    for (int i = 0; i < input_matrix.size(); i++)
    {
        result_vec[i] = vector_dot_product(input_matrix[i], input_vec);
    }

    return result_vec;
}

float sigmoid(float z)
{
    return 1 / (1 + exp(-z));
}

float predict(vector<vector<float>> features, vector<float> weights)
{
    
}

int main()
{
    float value = 4.5;
    float b0 = -100;
    float b1 = 0.6;
    cout << "Sigmoid of " << value << " = " << sigmoid(value) << endl;
    cout << "Logistic Regression:\n\tb0 = " << b0 << "\n\tb1 = " << b1 << endl;
    cout << "e1 = " << exp(1) << "\n"
         << endl;

    vector<float> vec_A = {1, 2, 3, 4};
    vector<float> vec_B = {5, 6, 7, 8};

    float dotProd = vector_dot_product(vec_A, vec_B);
    cout << "DOT product of A and B: " << dotProd << endl;
    return 0;
}
