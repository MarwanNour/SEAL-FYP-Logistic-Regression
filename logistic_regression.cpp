#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>
#include <string.h>
// #include <sstream>

using namespace std;

// Dot Product
float vector_dot_product(vector<float> vec_A, vector<float> vec_B)
{
    if (vec_A.size() != vec_B.size())
    {
        cerr << "Vector size mismatch" << endl;
        exit(1);
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
    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();
    vector<vector<float>> transposed(colSize, vector<float>(rowSize));

    for (int i = 0; i < rowSize; i++)
    {
        for (int j = 0; j < colSize; j++)
        {
            transposed[j][i] = input_matrix[i][j];
        }
    }

    // cout << "Line ---> " << __LINE__ << endl;

    return transposed;
}

// Linear Transformation (or Matrix * Vector)
vector<float> linear_transformation(vector<vector<float>> input_matrix, vector<float> input_vec)
{

    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();

    // cout << "rowSize  = " << rowSize << endl;
    // cout << "colSize  = " << colSize << endl;
    // cout << "vector size = " << input_vec.size() << endl;
    if (colSize != input_vec.size())
    {
        cerr << "Matrix Vector sizes error" << endl;
        exit(EXIT_FAILURE);
    }

    vector<float> result_vec(rowSize);
    for (int i = 0; i < input_matrix.size(); i++)
    {
        result_vec[i] = vector_dot_product(input_matrix[i], input_vec);
    }
    // cout << "Line ---> " << __LINE__ << endl;

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
    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;
    vector<float> lintransf_vec = linear_transformation(features, weights);

    vector<float> result_sigmoid_vec(features.size());

    for (int i = 0; i < result_sigmoid_vec.size(); i++)
    {
        result_sigmoid_vec[i] = sigmoid(lintransf_vec[i]);

        // DEBUG
        // cout << "lintransf_vec[i] = " << lintransf_vec[i] << endl;
        // cout << "result_sigmoid_vec[i] = " << result_sigmoid_vec[i] << endl;
        // if (i == 10)
        // {
        //     exit(0);
        // }
    }
    // cout << "Line ---> " << __LINE__ << endl;

    return result_sigmoid_vec;
}

// Cost Function
float cost_function(vector<vector<float>> features, vector<float> labels, vector<float> weights)
{

    // cout << "Func ---> " << __func__ << endl;

    int observations = labels.size();
    // cout << "Line ---> " << __LINE__ << endl;

    vector<float> predictions = predict(features, weights);

    // cout << "Line ---> " << __LINE__ << endl;

    vector<float> cost_result_vec(observations);
    float cost_sum = 0;

    for (int i = 0; i < observations; i++)
    {
        cout << "i = " << i << "\t\t";
        cout << "labels[i] = " << labels[i] << "\t\t";
        cout << "predictions[i] = " << predictions[i] << "\t\t";
        float cost0 = (1.0 - labels[i]) * log(1.0 - predictions[i]);
        float cost1 = (-labels[i]) * log(predictions[i]);

        cout << "cost 0 = " << cost0 << "\t\t";
        cout << "cost 1 = " << cost1 << "\t\t";

        cost_result_vec[i] = cost1 - cost0;
        cost_sum += cost_result_vec[i];
        cout << "cost sum = " << cost1 << endl;

        // // DEBUG
        // if (i == 100)
        // {
        //     exit(0);
        // }
    }

    float cost_result = cost_sum / observations;
    // cout << "Line ---> " << __LINE__ << endl;

    return cost_result;
}

// Gradient Descent (or Update Weights)
vector<float> update_weights(vector<vector<float>> features, vector<float> labels, vector<float> weights, float learning_rate)
{

    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    vector<float> new_weights(weights.size());

    int N = features.size();

    // Get predictions
    vector<float> predictions = predict(features, weights);
    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    // Tranpose features matrix
    vector<vector<float>> features_T = transpose_matrix(features);
    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    // Calculate Predictions - Labels vector
    vector<float> pred_labels(labels.size());
    for (int i = 0; i < labels.size(); i++)
    {
        pred_labels[i] = predictions[i] - labels[i];
    }

    // Calculate Gradient vector
    vector<float> gradient = linear_transformation(features_T, pred_labels);
    // cout << "Func ---> " << __func__ << endl;
    // cout << "Line ---> " << __LINE__ << endl;

    for (int i = 0; i < gradient.size(); i++)
    {
        // Divide by N to get average
        gradient[i] /= N;
        // Multiply by learning rate
        gradient[i] *= learning_rate;
        // Subtract from weights to minimize cost
        new_weights[i] = weights[i] - gradient[i];
    }
    // cout << "Line ---> " << __LINE__ << endl;

    return new_weights;
}

// Training
tuple<vector<float>, vector<float>> train(vector<vector<float>> features, vector<float> labels, vector<float> weights, float learning_rate, int iters)
{

    // cout << "Func ---> " << __func__ << endl;
    vector<float> new_weights(weights.size());
    vector<float> cost_history(iters);
    // cout << "Line ---> " << __LINE__ << endl;

    for (int i = 0; i < iters; i++)
    {
        // Get new weights
        new_weights = update_weights(features, labels, weights, learning_rate);
        // Get cost
        // cout << "Line ---> " << __LINE__ << endl;

        float cost = cost_function(features, labels, weights);
        cost_history[i] = cost;

        // Log Progress
        if (i % 10 == 0)
        {
            cout << "Iteration:\t" << i << "\t" << cost << endl;
            cout << "weights: ";
            for (int i = 0; i < weights.size(); i++)
            {
                cout << weights[i] << ", ";
            }
            cout << endl;
        }
    }
    return make_tuple(new_weights, cost_history);
}

// CSV to string matrix converter
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

// String matrix to float matrix converter
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

// Mean calculation
float getMean(vector<float> input_vec)
{
    float mean = 0;
    for (int i = 0; i < input_vec.size(); i++)
    {
        mean += input_vec[i];
    }
    mean /= input_vec.size();

    return mean;
}

// Standard Dev calculation
float getStandardDev(vector<float> input_vec, float mean)
{
    float variance = 0;
    for (int i = 0; i < input_vec.size(); i++)
    {
        variance += pow(input_vec[i] - mean, 2);
    }
    variance /= input_vec.size();

    float standard_dev = sqrt(variance);
    return standard_dev;
}

// Standard Scaler
vector<vector<float>> standard_scaler(vector<vector<float>> input_matrix)
{
    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();
    vector<vector<float>> result_matrix(rowSize, vector<float>(colSize));

    // Optimization: Get Means and Standard Devs first then do the scaling
    // first pass: get means and standard devs
    vector<float> means_vec(colSize);
    vector<float> stdev_vec(colSize);
    for (int i = 0; i < colSize; i++)
    {
        vector<float> column(rowSize);
        for (int j = 0; j < rowSize; j++)
        {
            column[j] = input_matrix[i][j];
        }
        means_vec[i] = getMean(column);
        stdev_vec[i] = getStandardDev(column, means_vec[i]);
    }

    // second pass: scale
    for (int i = 0; i < rowSize; i++)
    {
        for (int j = 0; j < colSize; j++)
        {
            result_matrix[i][j] = (input_matrix[i][j] - means_vec[j]) / stdev_vec[j];
        }
    }

    return result_matrix;
}

int main()
{
    float value = 2;
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
            cout << f_matrix[i][j] << ", ";
        }
        cout << endl;
    }
    cout << "..........." << endl;
    // Test print last 10 rows
    for (int i = f_matrix.size() - 10; i < f_matrix.size(); i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ", ";
        }
        cout << endl;
    }

    // Init features, labels and weights
    // Init features (rows of f_matrix , cols of f_matrix - 1)
    int rows = f_matrix.size();
    cout << "rows  = " << rows << endl;
    int cols = f_matrix[0].size() - 1;
    cout << "cols  = " << cols << endl;

    vector<vector<float>> features(rows, vector<float>(cols));
    // Init labels (rows of f_matrix)
    vector<float> labels(rows);
    // Init weight vector with zeros (cols of features)
    vector<float> weights(cols);

    // Fill the features matrix and labels vector
    for (int i = 0; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            features[i][j] = f_matrix[i][j];
        }
        labels[i] = f_matrix[i][cols];
    }

    // Fill the weights with random numbers (from 0 - 1)
    for (int i = 0; i < cols; i++)
    {
        weights[i] = ((double)rand() / (RAND_MAX)) + 1;
        cout << "weights[i] = " << weights[i] << endl;
    }

    // Test print the features and labels
    cout << "\nTesting features\n--------------\n"
         << endl;

    // Features Print test
    cout << "Features row size = " << features.size() << endl;
    cout << "Features col size = " << features[0].size() << endl;

    cout << "Labels row size = " << labels.size() << endl;
    cout << "Weights row size = " << weights.size() << endl;

    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < features[0].size(); j++)
        {
            cout << features[i][j] << ", ";
        }
        cout << endl;
    }

    // Standardize the features
    cout << "\nSTANDARDIZE TEST---------\n"
         << endl;

    vector<vector<float>> standard_features = standard_scaler(features);

    // Test print first 10 rows
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            cout << standard_features[i][j] << ", ";
        }
        cout << endl;
    }
    cout << "..........." << endl;
    // Test print last 10 rows
    for (int i = rows - 10; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            cout << standard_features[i][j] << ", ";
        }
        cout << endl;
    }

    
    // cout << "\nTesting labels\n--------------\n"
    //      << endl;

    // // Labels Print Test
    // for (int i = 0; i < 10; i++)
    // {
    //     cout << labels[i] << ", ";
    // }
    // cout << endl;

    // TRAIN
    // cout << "\nTraining--------------\n"
    //      << endl;
    // tuple<vector<float>, vector<float>> training_tuple = train(features, labels, weights, 0.1, 100);

    // vector<float> new_weights = get<0>(training_tuple);
    // vector<float> cost_history = get<1>(training_tuple);

    // // Print weights
    // cout << "\nNEW WEIGHTS\n------------------\n"
    //      << endl;
    // for (int i = 0; i < new_weights.size(); i++)
    // {
    //     cout << new_weights[i] << ", ";
    // }
    // cout << endl;

    return 0;
}
