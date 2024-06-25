#!/bin/bash

# Ensure script fails if any command fails
set -e

# Install the python3.12-venv package if not already installed
if ! dpkg -s python3.12-venv > /dev/null 2>&1; then
    sudo apt update
    sudo apt install -y python3.12-venv
fi

# Navigate to the app directory
cd /home/ubuntu/HospitalCare

sudo chown -R ubuntu:ubuntu /home/ubuntu/HospitalCare/
# Remove any existing virtual environment
sudo rm -rf venv

# Create a new virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
sudo chown -R ubuntu:ubuntu /home/ubuntu/HospitalCare/venv
# Add local bin to PATH
export PATH=$PATH:/home/ubuntu/.local/bin

# Install dependencies from requirements.txt
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Check if gunicorn is installed, install if not
if ! pip freeze | grep -q gunicorn; then
    echo "Gunicorn not found in venv, installing..."
    pip install gunicorn
fi

# Kill any running gunicorn processes
pgrep gunicorn && pkill gunicorn

# Start the Flask application using Gunicorn
echo "Starting the Flask application using Gunicorn..."
gunicorn -b 0.0.0.0:8000 app:app --daemon

# Restart nginx service
sudo systemctl restart nginx
