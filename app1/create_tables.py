#!/usr/bin/python
# -*- coding: utf-8 -*-
from extensions import db
from app import create_app  # Import the create_app function
from models import Monument
from sqlalchemy.exc import OperationalError
import csv
import time

def load_monuments_from_csv(csv_file_path, db):
    with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for row in reader:
            monument = Monument(name=row['NAZWA'], city=row['MIEJSCOWOSC'])
            db.session.add(monument)
        db.session.commit()

csv_file_path = 'V_OTWARTE_DANE_ZESTWIENIE_ZRN.csv'

app = create_app()  # Create an app instance using the factory function

trying = True
while trying:
    try:
        with app.app_context():  # Use the app context for database operations
            db.create_all()
            if Monument.query.first() is None:
                print("Loading data into Monument table from CSV...")
                load_monuments_from_csv(csv_file_path, db)  # Pass db as an argument
            trying = False
    except OperationalError as e:
        print(f"Waiting for the database... Error: {e}")
        time.sleep(10)

print("Database setup completed.")
