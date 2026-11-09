# ADITYA PR SMART PARK — Customer Account Edition

## Features
- Customer registration and login using mobile/email + password
- Passwords stored as salted PBKDF2 hashes
- Customer-only booking; anonymous visitors can view availability but must sign in to book
- My Bookings dashboard shows only the logged-in customer's bookings
- 100 parking slots numbered 1–100 in numerical order
- Booking ID confirmation and public booking lookup
- Admin login and dashboard, hourly price update, bill generation, partial/full payment recording
- Vehicle release blocked until full bill payment is recorded
- Existing `parking.db` is migrated by adding the customer table and booking user_id column; existing records are retained

## Run (Windows PowerShell)
```powershell
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Customer
- Register: `/register`
- Login: `/customer/login`
- My bookings: `/my-bookings`

## Admin demo login
- Username: `admin`
- Password: `admin123`

Change the Flask secret key and demo admin credentials before deployment. This academic demo records payments manually; it does not connect to UPI/card gateways. Use HTTPS, CSRF protection, rate limiting and production-grade admin authentication before public deployment.
