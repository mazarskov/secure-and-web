cmake_minimum_required(VERSION 3.23)

project(pm LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(pm src/main.c)