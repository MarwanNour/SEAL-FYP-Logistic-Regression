cmake_minimum_required(VERSION 3.10)
project(SEALDemo VERSION 1.0)
add_executable(sealdemo1 sealdemo1.cpp)
# add_executable(sealdemo2 sealdemo2.cpp)

find_package(SEAL)
target_link_libraries(sealdemo1 SEAL::seal)
# target_link_libraries(sealdemo2 SEAL::seal)


