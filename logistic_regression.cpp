#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>

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
	
	for(int i = 0; i < result_sigmoid_vec.size(); i++) {
		
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
	
	for(int i = 0; i < observations; i++)
	{
		float cost0 = (1-labels[i])*log(1 - predictions[i]);
		float cost1 = (-labels[i])*log(predictions[i]);
		
		cost_result_vec[i] = cost1 - cost0;
		cost_sum += cost_result_vec[i];
	}
	
	float cost_result = cost_sum / observations;
	
	return cost_result;
}


vector<float> update_weights(vector<vector<float>> features, vector<float> labels, vector<float> weights, float learning_rate)
{
	vector<float> new_weights;
	
	int N = features.size();
	
	// Get predictions
	vector<float> predictions = predict(features, weights);


	return new_weights;
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
