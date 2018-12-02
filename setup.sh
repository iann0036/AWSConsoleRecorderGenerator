#!/bin/bash

git clone https://github.com/boto/botocore

python preprocess.py

python genreport.py
