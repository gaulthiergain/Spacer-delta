# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++20 -Wall -Wextra -Wpedantic -O3 #-Werror -g

# Source and header file directories
SRC_DIR = src
BUILD_DIR = build

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# Header files
HDRS = $(wildcard $(SRC_DIR)/*.hpp)

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# Executable
TARGET = delta-versioner

# Rule to create the build directory if it doesn't exist
$(shell mkdir -p $(BUILD_DIR))

# Rule to compile .cpp to .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to build the executable
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) main.cpp $(OBJS) -o $@

# Rule to build the executable and move it to the root folder
$(TARGET): $(BUILD_DIR)/$(TARGET)
	cp $< .

# Default target
all: $(TARGET)

# Clean rule
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
