# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)	# Some previous versions of cmake choke on the BOM in UTF-8-encoded CMakeLists.txt files

project ("sudprelay" LANGUAGES "C" VERSION 0.5.0.0) 
# Sets the following variables:
#   PROJECT_NAME = "sudprelay"
#   PROJECT_SOURCE_DIR = "sudprelay_SOURCE_DIR" = <current directory>?
#   PROJECT_BINARY_DIR = "sudprelay_BINARY_DIR" = <current directory>?
#   PROJECT_VERSION = "sudprelay_VERSION" = 0
#   PROJECT_VERSION_MAJOR = "sudprelay_VERSION_MAJOR" = 5
#   PROJECT_VERSION_MINOR, "sudprelay_VERSION_MINOR" = 0
#   PROJECT_VERSION_PATCH, "sudprelay_VERSION_PATCH" = 0
#   PROJECT_VERSION_TWEAK, "sudprelay_VERSION_TWEAK" = ""
# Enables Language "C"


# Include sub-projects.
add_subdirectory("sudprelay") # Process ./sudprelay/CMakeLists.txt now

