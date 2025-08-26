from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from config import DevelopmentConfig  # Switch to ProductionConfig for prod
from datetime import datetime, timedelta
import random
import logging
from logging.handlers import TimedRotatingFileHandler
from functools import wraps
import bcrypt
import requests
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.graphics.barcode import code128  # For realistic barcode
from io import BytesIO
import smtplib
import re
from email.message import EmailMessage
import threading

# App Setup
app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # Make sure this matches your config
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# Enable CORS with more permissive settings for development
cors = CORS()
cors.init_app(
    app,
    resources={
        r"/*": {
            "origins": ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept"],
            "supports_credentials": True,
            "expose_headers": ["Content-Disposition", "X-Cancel-Nonce", "X-No-Registrations"]
        }
    },
    supports_credentials=True
)

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    # Dynamically set CORS for allowed dev origins
    allowed_origins = {
        'http://localhost:5173',
        'http://127.0.0.1:5173',
    }
    # Include any origins provided via env var ALLOWED_ORIGINS (comma-separated)
    extra = os.getenv('ALLOWED_ORIGINS', '')
    if extra:
        for o in [x.strip() for x in extra.split(',') if x.strip()]:
            allowed_origins.add(o)
    # Also allow a single FRONTEND_ORIGIN env var (common for one-frontend setups)
    frontend_origin = os.getenv('FRONTEND_ORIGIN')
    if frontend_origin and frontend_origin.strip():
        allowed_origins.add(frontend_origin.strip())
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    # Common headers
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Requested-With,Accept'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS,PATCH'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

jwt = JWTManager(app)

client = MongoClient(app.config['MONGO_URI'], tls=True, tlsAllowInvalidCertificates=True)
db = client['airline_booking']

# Logging Setup
if not app.debug:
    handler = TimedRotatingFileHandler('app.log', when='midnight', interval=1, backupCount=7)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Custom Error Handlers (Unchanged)
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f'Internal Error: {str(e)}')
    return jsonify({'error': 'Internal Server Error'}), 500

# RBAC Decorator (Unchanged)
def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def wrapped(*args, **kwargs):
            claims = get_jwt()
            # Get role from the claims
            role = claims.get('role')
            if not role or role not in allowed_roles:
                return jsonify({'msg': 'Access denied'}), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Password Utils
def hash_password(password):
    if isinstance(password, str):
        password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

def verify_password(input_password, stored_hash):
    if isinstance(input_password, str):
        input_password = input_password.encode('utf-8')
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    return bcrypt.checkpw(input_password, stored_hash)

# Email Sending for OTP (Unchanged)
def send_otp_email(to_email, otp):
    sender_email = app.config['SENDER_EMAIL']
    sender_password = app.config['SENDER_PASSWORD']
    subject = "Your OTP for Login"
    body = f"Your OTP is {otp}. It expires in 5 minutes."
    message = EmailMessage()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        app.logger.info(f"OTP sent to {to_email}")
    except Exception as e:
        app.logger.error(f"Failed to send OTP: {e}")
        raise

# Enhanced PDF Generation (Full, with Realistic Design)
def generate_realistic_ticket_pdf(passenger_details, flight_name, seat_numbers, travel_class, source, destination, travel_date, departure_time, gate_number, boarding_time, airline_name):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Background and Border (Enhanced for realism)
    c.setFillColor(colors.lightgrey)
    c.rect(0, 0, width, height, fill=1)  # Light background
    c.setStrokeColor(colors.black)
    c.setLineWidth(2)
    c.rect(50, 100, width - 100, height - 200, stroke=1, fill=0)  # Main border

    # Airline Logo Simulation (Text-based, blue accent)
    c.setFillColor(colors.blue)
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(width / 2, height - 110, airline_name.upper())
    c.setFillColor(colors.black)
    c.setLineWidth(1)
    c.line(50, height - 130, width - 50, height - 130)  # Divider under logo

    # Ticket Title
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.darkblue)
    c.drawCentredString(width / 2, height - 160, "BOARDING PASS")
    c.setFillColor(colors.black)

    # Flight Info Section (Left column for details, right for codes)
    info_y = height - 200
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Passenger:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, passenger_details[0]['Name'])  # Primary passenger

    info_y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Flight:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, flight_name)

    info_y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "From:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, f"{source} → {destination}")

    info_y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Date / Time:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, f"{travel_date} / {departure_time}")

    info_y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Gate / Boarding:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, f"{gate_number} / {boarding_time}")

    info_y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Class / Seat:")
    c.setFont("Helvetica", 12)
    c.drawString(150, info_y, f"{travel_class} / {', '.join(seat_numbers)}")

    # Divider for sections
    c.setLineWidth(0.5)
    c.line(50, info_y - 10, width - 50, info_y - 10)

    # Passenger Details Section (Enhanced with numbering)
    info_y -= 40
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, info_y, "Passenger Details:")
    info_y -= 20
    c.setFont("Helvetica", 11)
    for i, passenger in enumerate(passenger_details):
        c.drawString(60, info_y, f"{i+1}. {passenger['Name']} (Age: {passenger['Age']}, Gender: {passenger['Gender']}, Seat: {seat_numbers[i]})")
        info_y -= 15

    # Instructions (Bottom left)
    info_y -= 20
    c.setFont("Helvetica-Oblique", 10)
    c.drawString(60, info_y, "Please arrive at the gate at least 30 minutes before boarding time.")
    info_y -= 15
    c.drawString(60, info_y, "Carry a valid ID and your ticket.")

    # Footer
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(width / 2, 80, f"Thank you for choosing {airline_name}!")

    # Add Realistic Barcode (Bottom right, like real tickets)
    barcode_value = f"{flight_name}-{departure_time}-{','.join(seat_numbers)}"  # Encoded data
    barcode = code128.Code128(barcode_value, barHeight=50, humanReadable=True)
    barcode.drawOn(c, width - 250, 100)  # Position at bottom right

    # Additional Design: Perforated line simulation (dashed line)
    c.setDash(6, 3)
    c.line(50, 150, width - 50, 150)  # Fake tear-off line

    c.save()
    buffer.seek(0)
    return buffer

# Full Send Confirmation Email (Adopted Completely from Original)
def send_confirmation_email(to_email, user_name, flight_name, seat_numbers, source, destination, start, end, gate_number, boarding_time, travel_class, airline_name, travel_date, passenger_details):
    sender_email = app.config['SENDER_EMAIL']
    sender_password = app.config['SENDER_PASSWORD']
    subject = "Your Flight Ticket Confirmation - Thank You for Choosing Us!"
    passenger_info = "\n".join(
        [f" - {p['Name']} (Age: {p['Age']}, Gender: {p['Gender']}, Seat: {seat_numbers[i]})" for i, p in enumerate(passenger_details)]
    )
    body = f""" 
Dear {user_name},

We are pleased to inform you that your flight ticket has been successfully booked with {airline_name}. Below are your travel details:

Flight Name: {flight_name}
From: {source} → To: {destination}
Date: {travel_date}
Departure: {start}, Arrival: {end}
Boarding Time: {boarding_time}, Gate: {gate_number}
Class: {travel_class}
Seats: {', '.join(seat_numbers)}
Passenger Details:
{passenger_info}

Please ensure you arrive at the gate at least 30 minutes before the boarding time and carry a valid ID along with your ticket.

Thank you for choosing {airline_name}. We wish you a pleasant and comfortable journey!

Warm regards,
HCL Airlines Team 
"""
    pdf_buffer = generate_realistic_ticket_pdf(
        passenger_details, flight_name, seat_numbers, travel_class, source, destination, travel_date, start, gate_number, boarding_time, airline_name
    )
    message = EmailMessage()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    message.add_attachment(pdf_buffer.getvalue(), maintype="application", subtype="pdf", filename="boarding_pass.pdf")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        app.logger.info("Confirmation email sent successfully.")
    except Exception as e:
        app.logger.error("Failed to send confirmation email:", e)
        raise

# Cancellation Email (new)
def send_cancellation_email(to_email, user_name, flight_name, seat_numbers, source, destination, start, end, travel_class, airline_name, travel_date, passenger_details):
    sender_email = app.config['SENDER_EMAIL']
    sender_password = app.config['SENDER_PASSWORD']
    subject = "Your Flight Booking Cancellation Confirmation"
    passenger_info = "\n".join(
        [f" - {p['Name']} (Age: {p['Age']}, Gender: {p['Gender']})" for p in passenger_details]
    )
    body = f"""
Dear {user_name},

This is to confirm that your booking has been cancelled successfully.

Flight Name: {flight_name}
From: {source} → To: {destination}
Date: {travel_date}
Original Departure: {start}, Arrival: {end}
Class: {travel_class}
Seats Cancelled: {', '.join(seat_numbers)}
Passenger(s):
{passenger_info}

If this cancellation was not initiated by you, please contact our support team immediately.

Regards,
HCL Airlines Team
"""
    message = EmailMessage()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        app.logger.info("Cancellation email sent successfully.")
    except Exception as e:
        app.logger.error(f"Failed to send cancellation email: {e}")
        # Do not raise; cancellation should still proceed

# Registration (Unchanged)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not all(key in data for key in ['email', 'password', 'name', 'age', 'gender', 'location', 'phone', 'role']):
        return jsonify({'msg': 'Missing fields'}), 400
    if data['role'] not in ['customer', 'employee']:
        return jsonify({'msg': 'Invalid role'}), 400
    # Check if email exists for the same role
    if db.users.find_one({'Email': data['email'], 'Role': data['role']}):
        return jsonify({'msg': f'Email already exists for a {data["role"]}'}), 409
    hashed_pw = hash_password(data['password'])
    user = {
        '_id': str(ObjectId()),
        'Name': data['name'],
        'Age': int(data['age']),
        'Gender': data['gender'],
        'Location': data['location'],
        'Email': data['email'],
        'Phone Number': data['phone'],
        'Password': hashed_pw,
        'Role': data['role']
    }
    db.users.insert_one(user)
    return jsonify({'msg': 'Registered successfully'}), 201

# Login (Unchanged)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if 'email' not in data or 'password' not in data or 'role' not in data:
        return jsonify({'msg': 'Missing email, password, or role'}), 400
    
    # Find user by email and role
    user = db.users.find_one({'Email': data['email'], 'Role': data['role']})
    if not user or not verify_password(data['password'], user['Password']):
        return jsonify({'msg': 'Invalid credentials'}), 401
        
    otp = ''.join(random.choice('0123456789') for _ in range(6))
    try:
        # Send OTP via email asynchronously to avoid blocking response
        threading.Thread(target=send_otp_email, args=(data['email'], otp), daemon=True).start()
        
        # Hash the OTP before storing
        hashed_otp = hash_password(otp)
        
        # Delete any existing OTPs for this email and role
        db.otps.delete_many({
            'email': data['email'],
            'role': data['role']
        })
        
        # Store the new OTP record
        otp_record = {
            'email': data['email'],
            'role': data['role'],
            'otp': hashed_otp,
            'expiration': datetime.now() + timedelta(minutes=5),
            'created_at': datetime.now()
        }
        db.otps.insert_one(otp_record)
        
        # For debugging - log that OTP was sent and stored
        app.logger.info(f'OTP sent to {data["email"]} and stored in database')
        
        return jsonify({'msg': 'OTP sent to email'}), 200
        
    except Exception as e:
        app.logger.error(f'Error in login: {str(e)}')
        app.logger.error(traceback.format_exc())
        return jsonify({'msg': 'Failed to process login request'}), 500

# Verify OTP (Unchanged)
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    try:
        app.logger.info('=== OTP Verification Started ===')
        data = request.get_json()
        
        # Log request data (without sensitive info)
        app.logger.info(f'Request data: email={data.get("email")}, role={data.get("role")}')
        
        # Validate required fields
        if not all(k in data for k in ['email', 'otp', 'role']):
            app.logger.error('Missing required fields')
            return jsonify({'msg': 'Missing required fields: email, otp, or role'}), 400
        
        # Find OTP record
        otp_entry = db.otps.find_one({
            'email': data['email'],
            'role': data['role']
        })
        
        if not otp_entry:
            app.logger.error(f'No OTP record found for email: {data["email"]}')
            return jsonify({'msg': 'No OTP record found for this email'}), 401
        
        # Log the stored and received OTP (for debugging only - remove in production)
        app.logger.info(f'Stored OTP hash: {otp_entry["otp"]}')
        app.logger.info(f'Received OTP: {data["otp"]}')
            
        # Check if OTP is expired
        if otp_entry['expiration'] < datetime.now():
            app.logger.error(f'OTP expired for email: {data["email"]}')
            db.otps.delete_one({'_id': otp_entry['_id']})
            return jsonify({'msg': 'OTP has expired'}), 401
            
        # Verify OTP using the hashed version
        if not verify_password(data['otp'], otp_entry['otp']):
            app.logger.error(f'Invalid OTP for email: {data["email"]}')
            # For debugging - check if OTP matches without hashing (temporary)
            if data['otp'] == otp_entry['otp']:
                app.logger.error('OTP matches without hashing - password hashing issue detected')
            return jsonify({'msg': 'Invalid OTP'}), 401
            
        # Verify user exists with the specified role
        user = db.users.find_one({'Email': data['email'], 'Role': data['role']})
        if not user:
            app.logger.error(f'User {data["email"]} not found with role {data["role"]}')
            return jsonify({'msg': 'User not found with the specified role'}), 404
        
        # Generate JWT token with user details
        access_token = create_access_token(
            identity=user['Email'],
            additional_claims={
                'role': user['Role'],
                'email': user['Email'],
                'name': user.get('Name', '')
            },
            expires_delta=timedelta(days=1)
        )
        
        # Clean up OTP after successful verification
        db.otps.delete_one({'_id': otp_entry['_id']})
        
        # Prepare user data to return (without sensitive info)
        user_data = {
            'id': str(user['_id']),
            'email': user['Email'],
            'role': user['Role'],
            'name': user.get('Name', '')
        }
        
        app.logger.info(f'OTP verified successfully for {data["email"]}')
        
        return jsonify({
            'access_token': access_token,
            'user': user_data,
            'message': 'Login successful'
        }), 200
        
    except Exception as e:
        app.logger.error(f'OTP Verification Error: {str(e)}')
        app.logger.error(traceback.format_exc())
        return jsonify({'msg': 'Internal server error during OTP verification'}), 500

# Profile (Unchanged)
@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    try:
        # Get identity and role from JWT
        user_email = get_jwt_identity()
        claims = get_jwt()
        role = claims.get('role')
        if not user_email or not role:
            app.logger.error('Missing email or role in JWT token')
            return jsonify({'msg': 'Invalid token'}), 401

        app.logger.info(f'Looking up user with email: {user_email} and role: {role}')
        user = db.users.find_one({'Email': user_email, 'Role': role})
        if not user:
            app.logger.error(f'User not found for email: {user_email} and role: {role}')
            return jsonify({'msg': 'User not found'}), 404

        app.logger.info(f'Found user with role match: {user}')

        if request.method == 'GET':
            return jsonify({
                'name': user['Name'],
                'age': user['Age'],
                'gender': user['Gender'],
                'location': user['Location'],
                'email': user['Email'],
                'phone': user['Phone Number'],
                'role': user['Role']
            }), 200

        # Handle PUT request
        elif request.method == 'PUT':
            data = request.json
            if not data:
                return jsonify({'msg': 'No data provided'}), 400

            update_data = {}
            for key in ['name', 'age', 'gender', 'location', 'phone']:
                if key in data:
                    update_data[key.capitalize() if key != 'phone' else 'Phone Number'] = data[key] if key != 'age' else int(data[key])
            if 'password' in data and data['password']:
                update_data['Password'] = hash_password(data['password'])

            if update_data:
                db.users.update_one({'_id': user['_id']}, {'$set': update_data})
                return jsonify({'msg': 'Profile updated successfully'}), 200

            return jsonify({'msg': 'No valid fields to update'}), 400

        return jsonify({'msg': 'Method not allowed'}), 405

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        app.logger.error(f'Error in profile endpoint: {str(e)}\n{error_details}')
        return jsonify({'msg': 'Internal server error', 'error': str(e)}), 500

# Add Flight (Unchanged)
@app.route('/flights', methods=['POST'])
@jwt_required()
@role_required('employee')
def add_flight():
    user_email = get_jwt_identity()
    data = request.json

    # Basic input presence validation
    required = ['flight_name', 'business_total', 'economy_total', 'source', 'destination', 'start_time', 'end_time', 'economy_cost', 'business_cost']
    if not all(k in data for k in required):
        return jsonify({'msg': 'Missing required fields'}), 400

    # Parse and validate datetimes (format: dd/MM/YYYY HH:mm)
    try:
        start_dt = datetime.strptime(data['start_time'], '%d/%m/%Y %H:%M')
        end_dt = datetime.strptime(data['end_time'], '%d/%m/%Y %H:%M')
    except Exception:
        return jsonify({'msg': 'Invalid date format. Use dd/MM/YYYY HH:mm'}), 400

    now = datetime.now()
    if start_dt <= now:
        return jsonify({'msg': 'Departure time must be in the future'}), 400
    if end_dt <= start_dt:
        return jsonify({'msg': 'Arrival time must be after departure time'}), 400
    if not str(data['source']).strip() or not str(data['destination']).strip():
        return jsonify({'msg': 'Source and destination are required'}), 400
    if str(data['source']).strip().lower() == str(data['destination']).strip().lower():
        return jsonify({'msg': 'Destination cannot be the same as source'}), 400

    flight_id = db.flights.insert_one({
        'Flight Name': data['flight_name'],
        'Business Total Seats': int(data['business_total']),
        'Economy Total Seats': int(data['economy_total']),
        'Source': data['source'],
        'Destination': data['destination']
    }).inserted_id
    db.schedules.insert_one({
        'Flight ID': flight_id,
        'Business Available Seats': int(data['business_total']),
        'Economy Available Seats': int(data['economy_total']),
        'Start Time': data['start_time'],
        'End Time': data['end_time'],
        'Economy Cost': int(data['economy_cost']),
        'Business Cost': int(data['business_cost']),
        'Employee': user_email
    })
    return jsonify({'msg': 'Flight added'}), 201

# Flight Suggestions (New)
@app.route('/flights/suggestions', methods=['GET'])
def flight_suggestions():
    """
    Public endpoint to fetch unique flight fields for auto-complete.
    Query params:
      - field: 'source' | 'destination' (default: 'source')
      - q: optional text to prefix-match (case-insensitive)
      - limit: optional max results (default: 15, capped at 50)
    Response: ["Mumbai", "New Delhi", ...]
    """
    try:
        field = (request.args.get('field') or 'source').strip().lower()
        q = (request.args.get('q') or '').strip()
        try:
            limit = min(max(int(request.args.get('limit', 15)), 1), 50)
        except Exception:
            limit = 15

        field_map = {
            'source': 'Source',
            'destination': 'Destination',
        }
        mongo_field = field_map.get(field)
        if not mongo_field:
            return jsonify({'msg': 'Invalid field. Use source or destination'}), 400

        pipeline = []
        if q:
            safe = re.escape(q)
            pipeline.append({'$match': {mongo_field: {'$regex': f'^{safe}', '$options': 'i'}}})
        pipeline.extend([
            {'$group': {'_id': f'${mongo_field}'}},
            {'$sort': {'_id': 1}},
            {'$limit': limit}
        ])

        results = list(db.flights.aggregate(pipeline))
        suggestions = [r['_id'] for r in results if r.get('_id')]
        return jsonify(suggestions), 200
    except Exception as e:
        app.logger.error(f"Suggestions error: {e}")
        return jsonify({'msg': 'Failed to load suggestions'}), 500

# Search Flights (Unchanged)
@app.route('/flights/search', methods=['POST'])
@jwt_required()
def search_flights():
    data = request.json
    current_time = datetime.now()
    matching_flights = list(db.flights.find({
        'Source': data['source'],
        'Destination': data['destination']
    }))
    filtered = []
    for flight in matching_flights:
        schedule = db.schedules.find_one({'Flight ID': flight['_id']})
        if schedule:
            try:
                flight_time = datetime.strptime(schedule['Start Time'], '%d/%m/%Y %H:%M')
                if flight_time > current_time:
                    filtered.append({
                        'flight_name': flight['Flight Name'],
                        'source': flight['Source'],
                        'destination': flight['Destination'],
                        'start_time': schedule['Start Time'],
                        'end_time': schedule['End Time'],
                        'business_available': schedule['Business Available Seats'],
                        'economy_available': schedule['Economy Available Seats'],
                        'business_cost': schedule['Business Cost'],
                        'economy_cost': schedule['Economy Cost']
                    })
            except:
                pass
    return jsonify(filtered), 200

# Book Ticket (Unchanged, calls updated PDF/email)
@app.route('/bookings/book', methods=['POST'])
@jwt_required()
@role_required('customer')
def book_ticket():
    user_email = get_jwt_identity()
    user = db.users.find_one({'Email': user_email})
    data = request.json
    flight = db.flights.find_one({'Flight Name': data['flight_name']})
    if not flight:
        return jsonify({'msg': 'Flight not found'}), 404
    schedule = db.schedules.find_one({'Flight ID': flight['_id']})
    seat_class = data['class'].capitalize()
    seats_requested = int(data['seats_requested'])
    available = schedule[f'{seat_class} Available Seats']
    if available < seats_requested:
        return jsonify({'msg': 'Insufficient seats'}), 400
    # Normalize passenger fields to expected schema with capitalized keys
    raw_passengers = data.get('passengers', [])
    try:
        passengers = [
            {
                'Name': (p.get('Name') or p.get('name') or '').strip(),
                'Age': int(p.get('Age') if p.get('Age') is not None else p.get('age')),
                'Gender': (p.get('Gender') or p.get('gender') or '').strip(),
                'Passport': (p.get('Passport') or p.get('passport') or 'P1234567').strip()
            }
            for p in raw_passengers
        ]
    except Exception:
        return jsonify({'msg': 'Invalid passenger details'}), 400

    # Basic validation
    if any(not pr['Name'] or pr['Age'] is None or pr['Gender'] not in ['M', 'F', 'O'] for pr in passengers):
        return jsonify({'msg': 'Please provide valid Name, Age and Gender (M/F/O) for all passengers'}), 400

    if len(passengers) != seats_requested:
        return jsonify({'msg': 'Passenger mismatch'}), 400

    # Prevent duplicate booking for the same flight by the same customer with same passenger details
    # Build a set of incoming passenger identifiers (Name|Age|Gender)
    incoming_keys = {f"{p['Name'].strip().lower()}|{p['Age']}|{p['Gender'].upper()}" for p in passengers}
    existing = list(db.bookings.find({
        'Flight ID': flight['_id'],
        'Customer ID': user['_id']
    }))
    for b in existing:
        for ep in b.get('Passengers', []):
            key = f"{str(ep.get('Name','')).strip().lower()}|{ep.get('Age')}|{str(ep.get('Gender','')).upper()}"
            if key in incoming_keys:
                return jsonify({'msg': 'Duplicate passenger detected for this flight. The same person cannot be booked again for the same flight.'}), 409
    prefix = 'B' if seat_class == 'Business' else 'E'
    seat_numbers = [f"{prefix}{i+1}" for i in range(available - seats_requested, available)]
    cost = schedule[f'{seat_class} Cost']
    total_cost = cost * seats_requested
    db.schedules.update_one({'_id': schedule['_id']}, {'$inc': {f'{seat_class} Available Seats': -seats_requested}})
    booking_id = db.bookings.insert_one({
        'Flight ID': flight['_id'],
        'Customer ID': user['_id'],
        'Seats Booked': seat_numbers,
        'Class': seat_class,
        'Cost Per Seat': cost,
        'Total Cost': total_cost,
        'Passengers': passengers,
        'Status': 'Confirmed'
    }).inserted_id
    travel_date = schedule['Start Time'].split(' ')[0]
    # Attempt to send email, but don't fail the booking if email sending fails
    try:
        send_confirmation_email(
            user['Email'], user['Name'], flight['Flight Name'], seat_numbers, flight['Source'], flight['Destination'],
            schedule['Start Time'], schedule['End Time'], '18', '30 mins before departure', seat_class, 'HCL Airlines', travel_date, passengers
        )
    except Exception as e:
        app.logger.error(f'Failed to send confirmation email for booking {booking_id}: {e}')
    return jsonify({'msg': 'Booking successful', 'booking_id': str(booking_id), 'total_cost': total_cost}), 201

# View Bookings (Unchanged)
@app.route('/bookings', methods=['GET'])
@role_required('customer')
def view_bookings():
    claims = get_jwt()
    user = db.users.find_one({'Email': claims['email']})
    bookings = list(db.bookings.find({'Customer ID': user['_id']}))
    result = []
    for b in bookings:
        flight = db.flights.find_one({'_id': b['Flight ID']})
        schedule = db.schedules.find_one({'Flight ID': b['Flight ID']})
        result.append({
            'booking_id': str(b['_id']),
            'flight_name': flight['Flight Name'] if flight else 'Unknown',
            'class': b['Class'],
            'seats': b['Seats Booked'],
            'cost_per_seat': b['Cost Per Seat'],
            'total_cost': b['Total Cost'],
            'source': flight['Source'] if flight else 'Unknown',
            'destination': flight['Destination'] if flight else 'Unknown',
            'start': schedule['Start Time'] if schedule else 'Unknown',
            'end': schedule['End Time'] if schedule else 'Unknown',
            'status': b.get('Status', 'Confirmed'),
            'passengers': b['Passengers']
        })
    return jsonify(result), 200

# Cancel Booking (Unchanged)
@app.route('/bookings/cancel', methods=['POST'])
@role_required('customer')
def cancel_booking():
    claims = get_jwt()
    user = db.users.find_one({'Email': claims['email']})
    data = request.json
    booking = db.bookings.find_one({'_id': ObjectId(data['booking_id']), 'Customer ID': user['_id']})
    if not booking:
        return jsonify({'msg': 'Booking not found'}), 404

    # Gather details before deletion for email
    seat_numbers = booking.get('Seats Booked', [])
    seat_count = len(seat_numbers)
    seat_class = booking.get('Class', 'Economy')
    passengers = booking.get('Passengers', [])
    flight = db.flights.find_one({'_id': booking['Flight ID']})
    schedule = db.schedules.find_one({'Flight ID': booking['Flight ID']})

    # Send cancellation email (best-effort)
    try:
        if flight and schedule:
            travel_date = (schedule.get('Start Time') or '').split(' ')[0]
            send_cancellation_email(
                to_email=user['Email'],
                user_name=user.get('Name', ''),
                flight_name=flight.get('Flight Name', 'Unknown'),
                seat_numbers=seat_numbers,
                source=flight.get('Source', 'Unknown'),
                destination=flight.get('Destination', 'Unknown'),
                start=schedule.get('Start Time', ''),
                end=schedule.get('End Time', ''),
                travel_class=seat_class,
                airline_name='HCL Airlines',
                travel_date=travel_date,
                passenger_details=passengers
            )
    except Exception as e:
        app.logger.error(f"Cancellation email error for booking {booking.get('_id')}: {e}")

    # Restore seats and delete booking
    db.schedules.update_one({'Flight ID': booking['Flight ID']}, {'$inc': {f'{seat_class} Available Seats': seat_count}})
    db.bookings.delete_one({'_id': booking['_id']})
    return jsonify({'msg': 'Cancellation successful'}), 200

# View Customers 
@app.route('/customers', methods=['GET'])
@jwt_required()
@role_required('employee')
def view_customers():
    user_email = get_jwt_identity()
    customers = list(db.users.find({'Role': 'customer'}))
    result = []
    for user in customers:
        bookings = list(db.bookings.find({'Customer ID': user['_id']}))
        user_bookings = []
        for b in bookings:
            flight = db.flights.find_one({'_id': b['Flight ID']})
            user_bookings.append({
                'flight_name': flight['Flight Name'] if flight else 'Unknown',
                'class': b['Class'],
                'seats': b['Seats Booked'],
                'status': b.get('Status', 'Confirmed'),
                'passengers': b['Passengers']
            })
        result.append({
            'user_id': str(user['_id']),
            'name': user['Name'],
            'age': user['Age'],
            'gender': user['Gender'],
            'location': user['Location'],
            'email': user['Email'],
            'phone': user['Phone Number'],
            'bookings': user_bookings
        })
    return jsonify(result), 200

# Check Weather (Enhanced: optional selected flight IDs)
@app.route('/weather/check', methods=['GET'])
@jwt_required()
@role_required('employee')
def check_weather():
    user_email = get_jwt_identity()
    current_time = datetime.now()
    one_hour_later = current_time + timedelta(hours=1)
    # Optional filter by selected flight IDs: ?ids=comma,separated,ids
    ids_param = (request.args.get('ids') or '').strip()
    id_set = None
    if ids_param:
        try:
            id_set = {ObjectId(x.strip()) for x in ids_param.split(',') if x.strip()}
        except Exception:
            return jsonify({'msg': 'Invalid flight id(s)'}), 400
    schedules_list = list(db.schedules.find())
    cancellations = []

    # Thresholds (env-backed)
    try:
        WIND_KMPH_THRESHOLD = int(os.getenv('WIND_KMPH_THRESHOLD', '84'))
    except Exception:
        WIND_KMPH_THRESHOLD = 84
    try:
        HUMIDITY_THRESHOLD = int(os.getenv('HUMIDITY_THRESHOLD', '95'))
    except Exception:
        HUMIDITY_THRESHOLD = 95

    # Simple in-memory cache for this request
    weather_cache = {}

    def get_city_weather(city):
        key = city.strip().lower()
        if key in weather_cache:
            return weather_cache[key]
        url = f'https://wttr.in/{city}?format=j1'
        resp = requests.get(url, timeout=10)
        data = resp.json()
        curr = data.get('current_condition', [{}])[0]
        result = {
            'wind': int(curr.get('windspeedKmph') or 0),
            'humidity': int(curr.get('humidity') or 0)
        }
        weather_cache[key] = result
        return result

    for schedule in schedules_list:
        flight = db.flights.find_one({'_id': schedule['Flight ID']})
        if not flight:
            continue
        if id_set is not None and flight['_id'] not in id_set:
            continue
        try:
            flight_time = datetime.strptime(schedule['Start Time'], '%d/%m/%Y %H:%M')
            if flight_time > one_hour_later:
                src = flight.get('Source', '')
                dst = flight.get('Destination', '')
                # Fetch both cities with caching
                try:
                    src_w = get_city_weather(src)
                    dst_w = get_city_weather(dst)
                except Exception as we:
                    app.logger.error(f"Weather fetch failed for {src}/{dst}: {we}")
                    continue

                # Decide cancellation if either city exceeds threshold
                severe = (
                    src_w['wind'] >= WIND_KMPH_THRESHOLD or
                    dst_w['wind'] >= WIND_KMPH_THRESHOLD or
                    src_w['humidity'] >= HUMIDITY_THRESHOLD or
                    dst_w['humidity'] >= HUMIDITY_THRESHOLD
                )

                if severe:
                    # Gather all bookings for this flight
                    affected_bookings = list(db.bookings.find({'Flight ID': flight['_id']}))
                    # Send cancellation email per customer with details
                    for b in affected_bookings:
                        try:
                            customer = db.users.find_one({'_id': b['Customer ID']})
                            sched = db.schedules.find_one({'Flight ID': b['Flight ID']}) or {}
                            travel_date = (sched.get('Start Time') or '').split(' ')[0]
                            send_cancellation_email(
                                to_email=customer.get('Email') if customer else '',
                                user_name=(customer.get('Name') if customer else ''),
                                flight_name=flight.get('Flight Name', 'Unknown'),
                                seat_numbers=b.get('Seats Booked', []),
                                source=flight.get('Source', 'Unknown'),
                                destination=flight.get('Destination', 'Unknown'),
                                start=sched.get('Start Time', ''),
                                end=sched.get('End Time', ''),
                                travel_class=b.get('Class', 'Economy'),
                                airline_name='HCL Airlines',
                                travel_date=travel_date,
                                passenger_details=b.get('Passengers', [])
                            )
                        except Exception as e:
                            app.logger.error(f"Failed to send cancellation email for booking {b.get('_id')}: {e}")
                    # Remove all bookings for this flight after emails
                    db.bookings.delete_many({'Flight ID': flight['_id']})
                    # Remove the schedule so it no longer appears
                    db.schedules.delete_one({'_id': schedule['_id']})
                    cancellations.append(flight['Flight Name'])
        except Exception as e:
            app.logger.error(f"Error processing flight: {e}")
    return jsonify({'msg': 'Weather check complete', 'cancellations': cancellations}), 200

# Force Bad Weather flag for selected or all flights (no auto-cancel; for demo/testing)
@app.route('/weather/force_bad', methods=['POST'])
@jwt_required()
@role_required('employee')
def force_bad_weather():
    data = request.get_json() or {}
    ids = data.get('flight_ids') or []
    mode = (data.get('mode') or '').strip().lower()  # 'all' or 'selected'
    affected = []
    # We'll just return affected flight names for UI to allow cancel; no DB flag required
    try:
        if mode == 'all':
            schedules_list = list(db.schedules.find())
            for schedule in schedules_list:
                flight = db.flights.find_one({'_id': schedule['Flight ID']})
                if flight:
                    affected.append({'flight_id': str(flight['_id']), 'flight_name': flight.get('Flight Name', 'Unknown')})
        else:
            id_objs = []
            for fid in ids:
                try:
                    id_objs.append(ObjectId(str(fid)))
                except Exception:
                    return jsonify({'msg': f'Invalid flight id: {fid}'}), 400
            for oid in id_objs:
                flight = db.flights.find_one({'_id': oid})
                if flight:
                    affected.append({'flight_id': str(flight['_id']), 'flight_name': flight.get('Flight Name', 'Unknown')})
        return jsonify({'msg': 'Forced bad weather set for demo', 'affected': affected}), 200
    except Exception as e:
        app.logger.error(f'force_bad_weather error: {e}')
        return jsonify({'msg': 'Failed to set bad weather'}), 500

# List upcoming active flights (employee)
@app.route('/flights/active', methods=['GET'])
@jwt_required()
@role_required('employee')
def list_active_flights():
    now = datetime.now()
    results = []
    for schedule in db.schedules.find():
        try:
            start_dt = datetime.strptime(schedule.get('Start Time', ''), '%d/%m/%Y %H:%M')
        except Exception:
            continue
        if start_dt <= now:
            continue
        flight = db.flights.find_one({'_id': schedule['Flight ID']})
        if not flight:
            continue
        results.append({
            'flight_id': str(flight['_id']),
            'flight_name': flight.get('Flight Name', 'Unknown'),
            'source': flight.get('Source', ''),
            'destination': flight.get('Destination', ''),
            'start_time': schedule.get('Start Time', ''),
            'end_time': schedule.get('End Time', ''),
            'business_available': schedule.get('Business Available Seats', 0),
            'economy_available': schedule.get('Economy Available Seats', 0),
        })
    return jsonify(results), 200

# Export registered users for a flight as CSV and create a one-time cancel nonce
@app.route('/flights/<flight_id>/registrations/export', methods=['GET'])
@jwt_required()
@role_required('employee')
def export_flight_registrations(flight_id):
    try:
        oid = ObjectId(flight_id)
    except Exception:
        return jsonify({'msg': 'Invalid flight id'}), 400
    flight = db.flights.find_one({'_id': oid})
    if not flight:
        return jsonify({'msg': 'Flight not found'}), 404
    bookings = list(db.bookings.find({'Flight ID': oid}))
    # Build CSV content (prepend a commented nonce line for fallback parsing on the client)
    lines = [f'# CANCEL_NONCE,{""}', 'Booking ID,Customer Name,Customer Email,Customer Phone,Class,Seats,Passengers']
    for b in bookings:
        customer = db.users.find_one({'_id': b['Customer ID']})
        cname = (customer or {}).get('Name', '')
        cemail = (customer or {}).get('Email', '')
        cphone = (customer or {}).get('Phone Number', '')
        seats = ';'.join(b.get('Seats Booked', []))
        pax = ';'.join([f"{p.get('Name','')}|{p.get('Age','')}|{p.get('Gender','')}" for p in b.get('Passengers', [])])
        lines.append(f"{str(b.get('_id'))},{cname},{cemail},{cphone},{b.get('Class','')},{seats},{pax}")
    # Fill the nonce in the first line now that it's generated
    # Create a nonce and store
    nonce = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))
    lines[0] = f'# CANCEL_NONCE,{nonce}'
    csv_content = '\n'.join(lines)
    db.cancel_nonces.insert_one({
        'flight_id': oid,
        'nonce': nonce,
        'created_at': datetime.now(),
        'used': False
    })

    from flask import make_response
    resp = make_response(csv_content)
    resp.headers['Content-Type'] = 'text/csv'
    fname = f"registrations_{flight.get('Flight Name','flight').replace(' ', '_')}.csv"
    resp.headers['Content-Disposition'] = f'attachment; filename="{fname}"'
    # Send nonce via header so frontend can gate cancel
    resp.headers['X-Cancel-Nonce'] = nonce
    # Indicate if there were no registrations
    resp.headers['X-No-Registrations'] = 'true' if len(bookings) == 0 else 'false'
    return resp

# Cancel a flight: requires nonce from export endpoint; removes schedule and bookings
@app.route('/flights/<flight_id>/cancel', methods=['POST'])
@jwt_required()
@role_required('employee')
def cancel_flight(flight_id):
    data = request.get_json() or {}
    force = bool(data.get('force'))
    provided = data.get('cancel_nonce')
    if not provided and not force:
        return jsonify({'msg': 'cancel_nonce is required (download registrations first). To force-cancel, pass force=true.'}), 400
    try:
        oid = ObjectId(flight_id)
    except Exception:
        return jsonify({'msg': 'Invalid flight id'}), 400
    rec = None
    if not force:
        rec = db.cancel_nonces.find_one({'flight_id': oid, 'nonce': provided, 'used': False})
        if not rec:
            return jsonify({'msg': 'Invalid or used cancel nonce. Please download registrations again.'}), 400

    # Proceed with cancellation: delete bookings and schedule; keep flight doc to retain catalog if needed
    try:
        # Optional: notify customers (best effort)
        affected_bookings = list(db.bookings.find({'Flight ID': oid}))
        for b in affected_bookings:
            try:
                customer = db.users.find_one({'_id': b['Customer ID']})
                flight = db.flights.find_one({'_id': oid})
                sched = db.schedules.find_one({'Flight ID': oid}) or {}
                travel_date = (sched.get('Start Time') or '').split(' ')[0]
                send_cancellation_email(
                    to_email=(customer or {}).get('Email',''),
                    user_name=(customer or {}).get('Name',''),
                    flight_name=(flight or {}).get('Flight Name','Unknown'),
                    seat_numbers=b.get('Seats Booked', []),
                    source=(flight or {}).get('Source','Unknown'),
                    destination=(flight or {}).get('Destination','Unknown'),
                    start=sched.get('Start Time',''),
                    end=sched.get('End Time',''),
                    travel_class=b.get('Class','Economy'),
                    airline_name='HCL Airlines',
                    travel_date=travel_date,
                    passenger_details=b.get('Passengers', [])
                )
            except Exception as e:
                app.logger.error(f'Failed to notify on cancel: {e}')
        bookings_res = db.bookings.delete_many({'Flight ID': oid})
        sched_res = db.schedules.delete_many({'Flight ID': oid})
        try:
            app.logger.info(f"cancel_flight: deleted {bookings_res.deleted_count} bookings and {sched_res.deleted_count} schedules for flight {str(oid)}")
        except Exception:
            pass
        if rec:
            db.cancel_nonces.update_one({'_id': rec['_id']}, {'$set': {'used': True, 'used_at': datetime.now()}})
        return jsonify({'msg': 'Flight cancelled successfully'}), 200
    except Exception as e:
        app.logger.error(f'cancel_flight error: {e}')
        return jsonify({'msg': 'Failed to cancel flight'}), 500
# Statistics (Fixed with safe division and null handling)
@app.route('/stats', methods=['GET'])
@jwt_required()
@role_required('employee')
def statistics():
    try:
        user_email = get_jwt_identity()
        total_bookings = db.bookings.count_documents({})

        # Get total revenue
        revenue_result = list(db.bookings.aggregate([
            {'$match': {'Status': {'$ne': 'Flight Cancelled'}}},
            {'$group': {'_id': None, 'total': {'$sum': '$Total Cost'}}}
        ]))
        revenue = revenue_result[0]['total'] if revenue_result else 0

        # Get cancellation count
        cancellations = db.bookings.count_documents({'Status': 'Flight Cancelled'})

        # Calculate average passengers per booking
        avg_passengers_result = list(db.bookings.aggregate([
            {'$match': {'Status': {'$ne': 'Flight Cancelled'}}},
            {'$project': {'passenger_count': {'$size': '$Passengers'}}},
            {'$group': {'_id': None, 'avg': {'$avg': '$passenger_count'}}}
        ]))
        avg_passengers = round(avg_passengers_result[0]['avg'], 2) if avg_passengers_result and avg_passengers_result[0].get('avg') is not None else 0

        # Get gender distribution
        gender_dist = list(db.bookings.aggregate([
            {'$match': {'Status': {'$ne': 'Flight Cancelled'}}},
            {'$unwind': '$Passengers'},
            {'$group': {'_id': '$Passengers.Gender', 'count': {'$sum': 1}}},
            {'$project': {'_id': 0, 'gender': '$_id', 'count': 1}}
        ]))

        # Get top flights by passenger count
        top_flights = list(db.bookings.aggregate([
            {'$match': {'Status': {'$ne': 'Flight Cancelled'}}},
            {'$group': {
                '_id': '$Flight ID',
                'passengers': {'$sum': {'$size': '$Passengers'}},
                'revenue': {'$sum': '$Total Cost'}
            }},
            {'$lookup': {
                'from': 'flights',
                'localField': '_id',
                'foreignField': '_id',
                'as': 'flight'
            }},
            {'$unwind': '$flight'},
            {'$project': {
                'flight_name': '$flight.Flight Name',
                'passengers': 1,
                'revenue': 1
            }},
            {'$sort': {'passengers': -1}},
            {'$limit': 5}
        ]))

        # Get age group distribution
        age_groups = list(db.bookings.aggregate([
            {'$match': {'Status': {'$ne': 'Flight Cancelled'}}},
            {'$unwind': '$Passengers'},
            {'$bucket': {
                'groupBy': '$Passengers.Age',
                'boundaries': [0, 18, 35, 60, 100],
                'default': '100+',
                'output': {'count': {'$sum': 1}}
            }}
        ]))

        # Get flight utilization with safe division
        utilization = list(db.schedules.aggregate([
            {'$lookup': {
                'from': 'flights',
                'localField': 'Flight ID',
                'foreignField': '_id',
                'as': 'flight'
            }},
            {'$unwind': '$flight'},
            {'$project': {
                'flight_name': '$flight.Flight Name',
                'business_util': {
                    '$cond': {
                        'if': {'$eq': ['$flight.Business Total Seats', 0]},
                        'then': 0,
                        'else': {
                            '$multiply': [
                                {'$divide': [
                                    {'$subtract': [
                                        '$flight.Business Total Seats',
                                        '$Business Available Seats'
                                    ]},
                                    '$flight.Business Total Seats'
                                ]},
                                100
                            ]
                        }
                    }
                },
                'economy_util': {
                    '$cond': {
                        'if': {'$eq': ['$flight.Economy Total Seats', 0]},
                        'then': 0,
                        'else': {
                            '$multiply': [
                                {'$divide': [
                                    {'$subtract': [
                                        '$flight.Economy Total Seats',
                                        '$Economy Available Seats'
                                    ]},
                                    '$flight.Economy Total Seats'
                                ]},
                                100
                            ]
                        }
                    }
                }
            }}
        ]))

        # Format the response
        response_data = {
            'total_bookings': total_bookings,
            'revenue': revenue,
            'cancellations': cancellations,
            'avg_passengers_per_booking': avg_passengers,
            'gender_distribution': {item['gender']: item['count'] for item in gender_dist},
            'top_flights': [{
                'flight_name': f.get('flight_name', 'Unknown'),
                'passengers': f.get('passengers', 0),
                'revenue': f.get('revenue', 0)
            } for f in top_flights],
            'age_groups': [{
                'age_range': str(g.get('_id', 'Unknown')),
                'count': g.get('count', 0)
            } for g in age_groups],
            'flight_utilization': [{
                'flight_name': u.get('flight_name', 'Unknown'),
                'business_utilization': round(u.get('business_util', 0), 2),
                'economy_utilization': round(u.get('economy_util', 0), 2)
            } for u in utilization]
        }

        return jsonify(response_data), 200

    except Exception as e:
        app.logger.error(f'Error in statistics endpoint: {str(e)}')
        return jsonify({'msg': 'Error generating statistics', 'error': str(e)}), 500


if __name__ == '__main__':
    # Bind to 0.0.0.0 and use PORT from env for hosting providers (Render/Railway/etc.)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
