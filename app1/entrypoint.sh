#!/bin/bash
python3 create_tables.py
gunicorn -b :5000 app:app --log-level INFO