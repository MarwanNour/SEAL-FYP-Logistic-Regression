#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>
#include <string.h>
#include <sstream>

using namespace std;

// Dot Product
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

// Matrix Transpose
vector<vector<float>> transpose_matrix(vector<vector<float>> input_matrix)
{
    vector<vector<float>> transposed(input_matrix[0].size(), vector<float>(input_matrix.size()));

    for (int i = 0; i < input_matrix.size(); i++)
    {
        for (int j = 0; j < input_matrix[0].size(); j++)
        {
            transposed[i][j] = input_matrix[j][i];
        }
    }

    return transposed;
}

// Linear Transformation (or Matrix * Vector)
vector<float> linear_transformation(vector<vector<float>> input_matrix, vector<float> input_vec)
{
    vector<float> result_vec(input_vec.size());
    for (int i = 0; i < input_matrix.size(); i++)
    {
        result_vec[i] = vector_dot_product(input_matrix[i], input_vec);
    }

    return result_vec;
}

// Sigmoid
float sigmoid(float z)
{
    return 1 / (1 + exp(-z));
}

// Predict
vector<float> predict(vector<vector<float>> features, vector<float> weights)
{
    vector<float> lintransf_vec = linear_transformation(features, weights);

    vector<float> result_sigmoid_vec(features.size());

    for (int i = 0; i < result_sigmoid_vec.size(); i++)
    {

        result_sigmoid_vec[i] = sigmoid(lintransf_vec[i]);
    }
    return result_sigmoid_vec;
}

// Cost Function
float cost_function(vector<vector<float>> features, vector<float> labels, vector<float> weights)
{
    int observations = labels.size();
    vector<float> predictions = predict(features, weights);

    vector<float> cost_result_vec(observations);
    float cost_sum = 0;

    for (int i = 0; i < observations; i++)
    {
        float cost0 = (1 - labels[i]) * log(1 - predictions[i]);
        float cost1 = (-labels[i]) * log(predictions[i]);

        cost_result_vec[i] = cost1 - cost0;
        cost_sum += cost_result_vec[i];
    }

    float cost_result = cost_sum / observations;

    return cost_result;
}

// Gradient Descent (or Update Weights)
vector<float> update_weights(vector<vector<float>> features, vector<float> labels, vector<float> weights, float learning_rate)
{
    vector<float> new_weights(weights.size());

    int N = features.size();

    // Get predictions
    vector<float> predictions = predict(features, weights);

    // Tranpose features matrix
    vector<vector<float>> features_T = transpose_matrix(features);
    // Calculate Predictions - Labels vector
    vector<float> pred_labels(labels.size());
    for (int i = 0; i < labels.size(); i++)
    {
        pred_labels[i] = predictions[i] - labels[i];
    }
    // Calculate Gradient vector
    vector<float> gradient = linear_transformation(features_T, pred_labels);

    for (int i = 0; i < gradient.size(); i++)
    {
        // Divide by N to get average
        gradient[i] /= N;
        // Multiply by learning rate
        gradient[i] *= learning_rate;
        // Subtract from weights to minimize cost
        new_weights[i] = weights[i] - gradient[i];
    }

    return new_weights;
}

// Training
tuple<vector<float>, vector<float>> train(vector<vector<float>> features, vector<float> labels, vector<float> weights, float learning_rate, int iters)
{
    vector<float> new_weights(weights.size());
    vector<float> cost_history(iters);
    for (int i = 0; i < iters; i++)
    {
        // Get new weights
        new_weights = update_weights(features, labels, weights, learning_rate);
        // Get cost
        float cost = cost_function(features, labels, weights);
        cost_history[i] = cost;

        // Log Progress
        if (i % 1000 == 0)
        {
            cout << "Iteration:\t" << i << "\t" << cost << endl;
        }
    }
    return make_tuple(new_weights, cost_history);
}

vector<vector<string>> CSVtoMatrix(string filename)
{
    vector<vector<string>> result_matrix;

    ifstream data(filename);
    string line;
    int line_count = 0;
    while (getline(data, line))
    {
        stringstream lineStream(line);
        string cell;
        vector<string> parsedRow;
        while (getline(lineStream, cell, ','))
        {
            parsedRow.push_back(cell);
        }
        // Skip first line since it has text instead of numbers
        if (line_count != 0)
        {
            result_matrix.push_back(parsedRow);
        }
        line_count++;
    }
    return result_matrix;
}

vector<vector<float>> stringToFloatMatrix(vector<vector<string>> matrix)
{
    vector<vector<float>> result(matrix.size(), vector<float>(matrix[0].size()));
    for (int i = 0; i < matrix.size(); i++)
    {
        for (int j = 0; j < matrix[0].size(); j++)
        {
            result[i][j] = ::atof(matrix[i][j].c_str());
        }
    }

    return result;
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

    cout << "\n\n--------------------------\n"
         << endl;

    // Read File
    string filename = "pulsar_stars.csv";
    vector<vector<string>> s_matrix = CSVtoMatrix(filename);
    vector<vector<float>> f_matrix = stringToFloatMatrix(s_matrix);

    // Test print first 10 rows
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ",";
        }
        cout << endl;
    }
    cout << "..........." << endl;
    // Test print last 10 rows
    for (int i = f_matrix.size() - 10; i < f_matrix.size(); i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ",";
        }
        cout << endl;
    }

    // Size of features is the same as f_matrix but without the last column
    vector<vector<float>> features(f_matrix.size(), vector<float>(f_matrix[0].size() - 1));
    vector<float> labels(f_matrix.size());

    // Fill the features matrix and labels vector
    for (int i = 0; i < f_matrix.size(); i++)
    {
        for (int j = 0; j < f_matrix[0].size() - 1; j++)
        {
            features[i][j] = f_matrix[i][j];
        }
        labels[i] = f_matrix[i][f_matrix[0].size() - 1];
    }

    // Test print the features and labels

    cout << "\nTesting features\n--------------\n"
         << endl;

    // Features Print test
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < features[0].size(); j++)
        {
            cout << features[i][j] << ", ";
        }
        cout << endl;
    }

    cout << "\nTesting labels\n--------------\n"
         << endl;
    // Labels Print
    for (int i = 0; i < 10; i++)
    {
        cout << labels[i] << ", ";
    }
    cout << endl;

    return 0;
}
