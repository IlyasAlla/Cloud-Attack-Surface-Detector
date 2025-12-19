#!/bin/bash
set -e

# Assuming script is run from project root or we find the path
# We are in /home/me/Desktop/Pentester/projects/Cloud-Attack-Surface
PROJECT_ROOT=$(pwd)/cloud-attack-surface-detector
BIN_DIR=$PROJECT_ROOT/bin
SRC_DIR=$PROJECT_ROOT/src/python/orchestrator/projectdiscovery

mkdir -p $BIN_DIR

echo "Building Subfinder..."
cd $SRC_DIR/subfinder/cmd/subfinder
go build -o $BIN_DIR/subfinder .

echo "Building dnsx..."
cd $SRC_DIR/dnsx/cmd/dnsx
go build -o $BIN_DIR/dnsx .

echo "Building Naabu..."
cd $SRC_DIR/naabu/cmd/naabu
go build -o $BIN_DIR/naabu .

echo "Building Nuclei..."
cd $SRC_DIR/nuclei/cmd/nuclei
go build -o $BIN_DIR/nuclei .

echo "All tools built successfully!"
ls -l $BIN_DIR
