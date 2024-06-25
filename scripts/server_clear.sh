#!/bin/bash
# Ensure the ubuntu user owns all files and has permissions to remove them
sudo chown -R ubuntu:ubuntu /home/ubuntu/HospitalCare

# Attempt to remove the contents safely
rm -rf /home/ubuntu/HospitalCare/*
