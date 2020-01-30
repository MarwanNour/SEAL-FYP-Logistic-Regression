# SEALDemo
Microsoft SEAL Demo

## Setup for Linux
First, make sure you have Microsoft SEAL installed. Follow the tutorial on https://github.com/Microsoft/SEAL.
If you have made any changes to the file name or added other files you will need to modify the `CMakeLists.txt` file accordingly.

To Build the project for the first time you need to run `cmake .` to generate the proper Makefile then you can build it with `make`.

## Setup for Windows
Refer to the Windows installation of SEAL in https://github.com/Microsoft/SEAL.

Place the `.cpp` file(s) in the Source Files, and then build the project.