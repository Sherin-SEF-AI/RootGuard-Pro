#!/bin/bash

echo "Starting Linux Rootkit Detection Tool..."
echo

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This application requires root privileges."
   echo "Please run with sudo: sudo ./start_rootkit_detector.sh"
   echo
   exit 1
fi

echo "Root privileges confirmed."
echo

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed."
    echo "Please install Python3: sudo apt update && sudo apt install python3 python3-pip"
    exit 1
fi

echo "Python3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Installing pip3..."
    apt update && apt install python3-pip -y
fi

# Install system dependencies for PyQt6
echo "Installing system dependencies..."
apt update
apt install -y python3-pyqt6 python3-pyqt6.qtwidgets python3-dev build-essential

# Install Python dependencies
if [ -f requirements.txt ]; then
    echo "Installing/updating Python dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies."
        exit 1
    fi
fi

# Create necessary directories
mkdir -p logs data config reports

echo
echo "Starting Linux Rootkit Detection Tool..."

# Set DISPLAY for GUI (if running over SSH with X11 forwarding)
if [ -z "$DISPLAY" ]; then
    export DISPLAY=:0
fi

python3 main.py

if [ $? -ne 0 ]; then
    echo
    echo "Application exited with error code $?"
    read -p "Press Enter to continue..."
fi