#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>
#include <string.h>

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

    return transposed;
}

// Linear Transformation (or Matrix * Vector)
vector<float> linear_transformation(vector<vector<float>> input_matrix, vector<float> input_vec)
{

    int rowSize = input_matrix.size();
    int colSize = input_matrix[0].size();

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

        // DEBUG
        // cout << "lintransf_vec[i] = " << lintransf_vec[i] << endl;
        // cout << "result_sigmoid_vec[i] = " << result_sigmoid_vec[i] << endl;
        // if (i == 10)
        // {
        //     exit(0);
        // }
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

        // Handle Prediction = 1 issue: Epsilon subtraction
        float epsilon = 0.0001;
        if (predictions[i] == 1)
        {
            predictions[i] -= epsilon;
        }

        // Calculate Cost 0 and 1
        float cost0 = (1.0 - labels[i]) * log(1.0 - predictions[i]);
        float cost1 = (-labels[i]) * log(predictions[i]);

        cost_result_vec[i] = cost1 - cost0;
        cost_sum += cost_result_vec[i];

        // Log Progress
        if (i % 2000 == 0)
        {
            cout << "i = " << i << "\t\t";
            cout << "labels[i] = " << labels[i] << "\t\t";
            cout << "predictions[i] = " << predictions[i] << "\t\t";
            cout << "cost 0 = " << cost0 << "\t\t";
            cout << "cost 1 = " << cost1 << "\t\t";
            cout << "cost sum = " << cost_sum << endl;
        }

        // // DEBUG
        // if (i == 100)
        // {
        //     exit(0);
        // }
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

    int colSize = weights.size();
    vector<float> new_weights(colSize);
    vector<float> cost_history(iters);

    // Set temp weights
    vector<float> temp_weights(colSize);
    for (int i = 0; i < colSize; i++)
    {
        temp_weights[i] = weights[i];
    }

    for (int i = 0; i < iters; i++)
    {
        // Get new weights
        new_weights = update_weights(features, labels, temp_weights, learning_rate);

        // Get cost
        float cost = cost_function(features, labels, new_weights);
        cost_history[i] = cost;

        // Log Progress
        if (i % 100 == 0)
        {
            cout << "Iteration:\t" << i << "\t" << cost << endl;
            cout << "Weights: ";
            for (int i = 0; i < colSize; i++)
            {
                cout << new_weights[i] << ", ";
            }
            cout << endl;
        }

        // Set temp weights to new weights
        for (int j = 0; j < colSize; j++)
        {
            temp_weights[j] = new_weights[j];
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
            // cout << input_matrix[j][i] << ", ";
            column[j] = input_matrix[j][i];
            // cout << column[j] << ", ";
        }

        means_vec[i] = getMean(column);
        stdev_vec[i] = getStandardDev(column, means_vec[i]);
        // cout << "MEAN at i = " << i << ":\t" << means_vec[i] << endl;
        // cout << "STDV at i = " << i << ":\t" << stdev_vec[i] << endl;
    }

    // second pass: scale
    for (int i = 0; i < rowSize; i++)
    {
        for (int j = 0; j < colSize; j++)
        {
            result_matrix[i][j] = (input_matrix[i][j] - means_vec[j]) / stdev_vec[j];
            // cout << "RESULT at i = " << i << ":\t" << result_matrix[i][j] << endl;
        }
    }

    return result_matrix;
}

float accuracy(vector<float> predicted_labels, vector<float> actual_labels)
{
    // handle error
    if (predicted_labels.size() != actual_labels.size())
    {
        cerr << "Vector size mismatch" << endl;
        exit(EXIT_FAILURE);
    }

    int size = predicted_labels.size();
    vector<float> diff(size);
    int nnz = 0;
    for (int i = 0; i < size; i++)
    {
        diff[i] = predicted_labels[i] - actual_labels[i];
        // count non zero in diff
        if (diff[i] != 0)
        {
            nnz++;
        }
    }

    float result = 1.0 - (nnz / size);
    return result;
}

float RandomFloat(float a, float b)
{
    float random = ((float)rand()) / (float)RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

int main()
{
    // Read File
    string filename = "pulsar_stars.csv";
    vector<vector<string>> s_matrix = CSVtoMatrix(filename);
    vector<vector<float>> f_matrix = stringToFloatMatrix(s_matrix);

    // Test print first 10 rows
    cout << "First 10 rows of CSV file --------\n"
         << endl;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < f_matrix[0].size(); j++)
        {
            cout << f_matrix[i][j] << ", ";
        }
        cout << endl;
    }
    cout << "...........\nLast 10 rows of CSV file ----------\n"
         << endl;
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
    cout << "\nNumber of rows  = " << rows << endl;
    int cols = f_matrix[0].size() - 1;
    cout << "\nNumber of cols  = " << cols << endl;

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

    // Fill the weights with random numbers (from 1 - 2)
    for (int i = 0; i < cols; i++)
    {
        weights[i] = RandomFloat(-2, 2);
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

    cout << "\nTesting labels\n--------------\n"
         << endl;

    // Labels Print Test
    for (int i = 0; i < 10; i++)
    {
        cout << labels[i] << ", ";
    }
    cout << endl;

    // TRAIN
    cout << "\nTraining--------------\n"
         << endl;
    tuple<vector<float>, vector<float>> training_tuple = train(standard_features, labels, weights, 0.1, 100);

    vector<float> new_weights = get<0>(training_tuple);
    vector<float> cost_history = get<1>(training_tuple);

    // Print old weights
    cout << "\nOLD WEIGHTS\n------------------"
         << endl;
    for (int i = 0; i < weights.size(); i++)
    {
        cout << weights[i] << ", ";
    }
    cout << endl;

    // Print mew weights
    cout << "\nNEW WEIGHTS\n------------------"
         << endl;
    for (int i = 0; i < new_weights.size(); i++)
    {
        cout << new_weights[i] << ", ";
    }
    cout << endl;

    // Print Cost history
    cout << "\nCOST HISTORY\n------------------"
         << endl;
    for (int i = 0; i < cost_history.size(); i++)
    {
        cout << cost_history[i] << ", ";
        if (i % 10 == 0 && i > 0)
        {
            cout << "\n";
        }
    }
    cout << endl;

    // Print Accuracy
    cout << "\nACCURACY\n-------------------" << endl;
    
    return 0;
}
