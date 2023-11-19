#!/usr/bin/python
# -*- coding: utf-8 -*-
from app import app, db
from sqlalchemy.exc import OperationalError
import time

trying = True
while trying:
    try:
        with app.app_context():
            db.create_all()
        trying = False
    except OperationalError:
        print("Waiting for postgres...")
        time.sleep(10)
print("Databases created")
exit()
