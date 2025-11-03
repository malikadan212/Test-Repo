# Simple Makefile for test.cpp
CXX = g++
CXXFLAGS = -Wall -std=c++11

all: test

test: test.cpp
	$(CXX) $(CXXFLAGS) -o test test.cpp

clean:
	rm -f test test.exe

.PHONY: all clean
