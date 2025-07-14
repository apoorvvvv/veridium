#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, User

def test_user_model():
    with app.app_context():
        print("Testing User model...")
        
        # Create a user
        user = User.create_user("test_user", "Test User")
        print(f"User created: {user}")
        print(f"user.user_id: {repr(user.user_id)} (type: {type(user.user_id)})")
        print(f"user.user_name: {repr(user.user_name)} (type: {type(user.user_name)})")
        print(f"user.display_name: {repr(user.display_name)} (type: {type(user.display_name)})")
        
        # Add to database
        db.session.add(user)
        db.session.flush()
        print(f"After flush - user.user_id: {repr(user.user_id)} (type: {type(user.user_id)})")
        
        # Commit and reload
        db.session.commit()
        print(f"After commit - user.user_id: {repr(user.user_id)} (type: {type(user.user_id)})")
        
        # Query from database
        user_from_db = User.query.filter_by(user_name="test_user").first()
        if user_from_db:
            print(f"From DB - user.user_id: {repr(user_from_db.user_id)} (type: {type(user_from_db.user_id)})")
        else:
            print("User not found in database")

if __name__ == "__main__":
    test_user_model() 