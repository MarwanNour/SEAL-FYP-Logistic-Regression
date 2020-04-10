#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <cmath>
#include <vector>

using namespace std;

double getElementLogisticCost(double &x, int &y, double &a, double &b)
{
    double p = 1 / (1 + exp(-(a * x + b)));
    if (y == 1)
    {
        return -log(p);
    }
    else
    {
        return -log(1 - p);
    }
}

// slope:a
// intercept:b
// derivative of slope: da
// derivative of intercept: db

double getLogisticCost(vector<double> &x, vector<int> &y, double a, double b, double &da, double &db)
{
    int n = static_cast<int>(x.size());
    double cost = 0;
    da = 0;
    db = 0;

    for (int i = 0; i < n; i++)
    {
        cost += getElementLogisticCost(x[i], y[i], a, b);
        double eaxb = exp(a * x[i] + b);
        if (y[i] == 1)
        {
            da += -x[i] / (1 + eaxb);
            db += -1 / (1 + eaxb);
        }
        else
        {
            da += x[i] * eaxb / (1 + eaxb);
            db += eaxb / (1 + eaxb);
        }
    }
    cost /= n;
    da /= n;
    db /= n;
    return cost;
}

void logisticRegression(vector<double> &x, vector<int> &y, double slope = 1, double intercept = 0)
{
    double lrate = 0.0005;
    double threshold = 0.001;
    int iter = 0;

    while (true)
    {
        double da = 0;
        double db = 0;
        double cost = getLogisticCost(x, y, slope, intercept, da, db);

        if (iter % 1000 == 0)
        {
            cout << "Iter : " << iter << " cost = " << cost << " da = " << da << " db = " << db << endl;
        }
        iter++;
        if (abs(da) < threshold && abs(db) < threshold)
        {
            cout << "p = 1 / (1 + exp(-(" << slope << " * x + " << intercept << "))) " << endl;
            break;
        }
        slope -= lrate * da;
        intercept -= lrate * db;
    }
}

int main()
{
    vector<double> A;
    vector<int> B;
    // create a dataset with inputs and labels
    // for values [0, 20), assign label 0
    // for values [80,100) assign label 1
    for (int i = 0; i < 1000; i++)
    {
        A.push_back(rand() % 20);
        B.push_back(0);
        A.push_back(80 + rand() % 20);
        B.push_back(1);
    }
    // kick off our simple logisticRegression!
    logisticRegression(A, B);
    return 0;
}

