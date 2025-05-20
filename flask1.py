import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random
import pymysql
from datetime import datetime
import mysql.connector

import smtplib
app = Flask(__name__)
app.secret_key = 'register'


# Database config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'findaspot'
mysql = MySQL(app)

 
# Flask-Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'findaspot25@gmail.com'
app.config['MAIL_PASSWORD'] = 'ygzndsykjylisjyc'
mail = Mail(app)










@app.route("/")
def home():
    return render_template('index.html')




import os
from werkzeug.utils import secure_filename

# Configure upload folder (add this before your routes)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/services')
def services():
    return render_template('services.html')
@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = None
    if request.method == 'POST':
        try:
            # Get form data
            role = request.form['role']
            name = request.form['name']
            email = request.form['email']
            password = generate_password_hash(request.form['password'])
            otp = str(random.randint(1000, 9999))

            # Handle file upload
            profile_image = None
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Create uploads folder if it doesn't exist
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    profile_image = filepath  # Store relative path

            cursor = mysql.connection.cursor()

            # Check if email exists
            cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already registered', 'danger')
                return redirect(url_for('register'))

            # Insert user
            cursor.execute(
                "INSERT INTO users (role, name, email, password, otp) VALUES (%s, %s, %s, %s, %s)",
                (role, name, email, password, otp)
            )
            user_id = cursor.lastrowid

            # Insert customer profile (if customer)
            if role == 'customer':
                cursor.execute(
                    """INSERT INTO customer_profiles 
                    (user_id, name, phone_no, vehicle_no, age, gender, address, city, state, photo)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        user_id,
                        name,
                        request.form.get('phone_no'),
                        request.form.get('vehicle_no'),
                        request.form.get('age'),
                        request.form.get('gender'),
                        request.form.get('address'),
                        request.form.get('city'),
                        request.form.get('state'),
                        profile_image  # This can be None if no image uploaded
                    )
                )

            mysql.connection.commit()

            # Send OTP email
            msg = Message('Email Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your OTP for verification is: {otp}'
            mail.send(msg)

            flash('Registration successful! Check your email for OTP.', 'success')
            return redirect(url_for('verify_email', email=email))

        except Exception as e:
            if mysql.connection:
                mysql.connection.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('register'))

        finally:
            if cursor:
                cursor.close()

    return render_template('register.html')

@app.route('/verify_email/<email>', methods=['GET', 'POST'])
def verify_email(email):
    if request.method == 'POST':
        otp = request.form['otp']

        # Verify the OTP
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT otp FROM users WHERE email = %s", (email,))
        db_otp = cursor.fetchone()

        if db_otp and db_otp[0] == otp:
            cursor.execute("UPDATE users SET is_verified = 1 WHERE email = %s", (email,))
            mysql.connection.commit()
            cursor.close()
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            cursor.close()

    return render_template('verify_email.html', email=email)

@app.route('/resend_otp/<email>', methods=['GET'])
def resend_otp(email):
    # Generate a new OTP
    otp = str(random.randint(1000, 9999))

    # Update the OTP in the database for the given email
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE users SET otp = %s WHERE email = %s", (otp, email))
    mysql.connection.commit()
    cursor.close()

    # Send the new OTP email
    msg = Message('Email Verification', sender='your-email@gmail.com', recipients=[email])
    msg.body = f'Your new OTP for verification is: {otp}'
    mail.send(msg)

    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('verify_email', email=email))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Use .get() to avoid KeyError
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return render_template('login.html')

        # Validate user credentials
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT password, is_verified, role FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            db_password, is_verified, role = user
            if not is_verified:
                flash('Email not verified. Please verify your email.', 'warning')
            elif check_password_hash(db_password, password):
                session['user'] = email
                session['role'] = role  # Store the role in the session
                flash('Login successful!', 'success')

                # Redirect to the appropriate dashboard based on the role
                if role == 'customer':
                    return redirect(url_for('customer_dashboard'))
                elif role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Role not recognized.', 'danger')
            else:
                flash('Invalid credentials. Please try again.', 'danger')
        else:
            flash('Email not registered.', 'danger')
    return render_template('login.html')














@app.route('/customer_dashboard')
def customer_dashboard():
    if 'user' not in session:
        flash('Please login to access dashboard', 'warning')
        return redirect(url_for('login'))

    try:
        cursor = mysql.connection.cursor()
        
        # Get user details including name
        cursor.execute("""
            SELECT u.name, u.email 
            FROM users u
            WHERE u.email = %s
        """, (session['user'],))
        
        user_data = cursor.fetchone()
        
        if not user_data:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
            
        user_name = user_data[0]
        user_email = user_data[1]
        
        return render_template('customer_dashboard.html', 
                            user_name=user_name,
                            user_email=user_email)
        
    except Exception as e:
        print(f"Error fetching user data: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('login'))
    finally:
        if cursor:
            cursor.close()


@app.route('/login/dashboard/book_slot', methods=['GET', 'POST'])
def book_slot():
    if 'user' in session:
        return render_template('book_slot.html')
    flash('You need to login first.', 'warning')
    return redirect(url_for('login'))


@app.route('/confirm_slot')
def confirm_slot():
    name = request.args.get('name')
    address = request.args.get('address')
    return render_template('slot_confirmation.html', parking_name=name, parking_address=address)

@app.route('/my_bookings')
def my_bookings():
    if 'user' not in session:
        flash("Please log in to view your bookings.", "warning")
        return redirect(url_for('login'))

    user_email = session['user']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id FROM users WHERE email = %s", (user_email,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    user_id = user[0]

    # Get booking data joined with parking lot name
    query = """
        SELECT b.booking_id, pl.name, b.entry_time, b.exit_time, b.slot_no, b.status, b.amount
        FROM bookings b
        JOIN parking_lots pl ON b.parking_id = pl.parking_id
        WHERE b.user_id = %s
        ORDER BY b.entry_time DESC
    """
    cursor.execute(query, (user_id,))
    bookings = cursor.fetchall()
    cursor.close()

    return render_template("my_bookings.html", bookings=bookings)



































@app.route('/profile', methods=['GET', 'POST'])
def manage_profile():
    if 'user' not in session:
        flash('Please login to manage your profile', 'warning')
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    user_email = session['user']

    # Get user_id from users table
    cursor.execute("SELECT user_id FROM users WHERE email = %s", (user_email,))
    user_id = cursor.fetchone()[0]

    if request.method == 'POST':
        # Update profile data
        name = request.form.get('name')
        phone_no = request.form.get('phone_no')
        vehicle_no = request.form.get('vehicle_no')
        age = request.form.get('age')
        address = request.form.get('address')

        try:
            cursor.execute("""
                UPDATE customer_profiles 
                SET name = %s, phone_no = %s, vehicle_no = %s, age = %s, address = %s
                WHERE user_id = %s
            """, (name, phone_no, vehicle_no, age, address, user_id))
            mysql.connection.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash('Error updating profile: ' + str(e), 'danger')
        finally:
            cursor.close()
        return redirect(url_for('manage_profile'))

    # Fetch profile data
    cursor.execute("""
        SELECT name, phone_no, vehicle_no, age, address, photo 
        FROM customer_profiles 
        WHERE user_id = %s
    """, (user_id,))
    profile = cursor.fetchone()
    cursor.close()

    return render_template('profile.html', profile=profile)


@app.route('/payment_history')
def payment_history():
    if 'user' not in session:
        flash("Please log in to view your payment history.", "warning")
        return redirect(url_for('login'))

    user_email = session['user']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id FROM users WHERE email = %s", (user_email,))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    user_id = user[0]

    # Fetch payment history
    query = """
        SELECT payment_id, booking_id, amount, method, status, paid_at
        FROM payments
        WHERE user_id = %s
        ORDER BY paid_at DESC
    """
    cursor.execute(query, (user_id,))
    payments = cursor.fetchall()
    cursor.close()

    return render_template("payment_history.html", payments=payments)


@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not all([name, email, subject, message]):
            flash("All fields are required.", "warning")
            return redirect(url_for('support'))

        full_message = f"""
From: {name}
Email: {email}

Subject: {subject}

Message:
{message}
        """

        try:
            msg = Message(subject=f"[Find-A-Spot Support] {subject}",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=['findaspot25@gmail.com'],
                          body=full_message)
            mail.send(msg)
            flash("Your message has been sent successfully!", "success")
        except Exception as e:
            print(f"Error sending email: {e}")
            flash("Failed to send your message. Please try again later.", "danger")

        return redirect(url_for('support'))

    return render_template('support.html')














# yaha se admin login ke function honge

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied. Admin privileges required', 'warning')
        return redirect(url_for('login'))

    try:
        cursor = mysql.connection.cursor()
        
        # Get admin details including name
        cursor.execute("""
            SELECT name, email 
            FROM users 
            WHERE email = %s AND role = 'admin'
        """, (session['user'],))
        
        admin_data = cursor.fetchone()
        
        if not admin_data:
            flash('Admin account not found', 'danger')
            return redirect(url_for('login'))
            
        admin_name = admin_data[0]
        admin_email = admin_data[1]
        
        # Get admin stats (optional)
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM parking_lots")
        parking_count = cursor.fetchone()[0]
        
        return render_template('admin_dashboard.html', 
                            admin_name=admin_name,
                            admin_email=admin_email,
                            user_count=user_count,
                            parking_count=parking_count)
        
    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('login'))
    finally:
        if cursor:
            cursor.close()


@app.route('/admin/add_parking', methods=['GET', 'POST'])
def add_parking():
    if 'user' in session and session.get('role') == 'admin':  # Ensure only admin can access this page
        if request.method == 'POST':
            # Get form data
            name = request.form['name']
            parkingid = request.form['parking_id']
            parkingpassword = request.form['parking_password']
            address = request.form['address']
            coordinates = request.form['coordinates']
            capacity = request.form['capacity']
            price_per_hour = request.form['price_per_hour']
            type_ = request.form['type']
            contact_number = request.form['contact_number']

            # Insert data into the database
            cursor = mysql.connection.cursor()
            cursor.execute("""
                INSERT INTO parking_lots (Name, Address, coordinates, Capacity, Price_Per_Hour, Type, Contact_number, parking_id, parking_password)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (name, address, coordinates, capacity, price_per_hour, type_, contact_number, parkingid, parkingpassword))
            mysql.connection.commit()
            cursor.close()

            flash('Parking lot added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard after successful addition
        return render_template('admin_addparking.html')
    flash('Access restricted to admins only.', 'danger')
    return redirect(url_for('login'))





@app.route('/view_parking_lots')
def view_parking_lots():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Please login as a admin to view parking lots.', 'warning')
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT ID, Name, Address, Coordinates, Price_Per_Hour, Type, Contact_number, capacity
        FROM parking_lots
    """)
    parking_lots = cursor.fetchall()
    cursor.close()

    return render_template('view_parking_lots.html', parking_lots=parking_lots)



@app.route('/live_parking_info')
def live_parking_info_page():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT parking_id, Name, Address FROM parking_lots")
    parking_lots = cursor.fetchall()
    cursor.close()
    parking_lots = [{'parking_id': lot[0], 'Name': lot[1], 'Address': lot[2]} for lot in parking_lots]
    return render_template('live_parking_info.html', parking_lots=parking_lots)

@app.route('/api/live_parking_info')
def live_parking_info_api():
    parking_id = request.args.get('parking_id')
    if not parking_id:
        return {'slots': []}

    cursor = mysql.connection.cursor()
    query = """
        SELECT slot_no, is_occupied, vehicle_no, entry_time 
        FROM real_time_parking_info
        WHERE parking_id = %s ORDER BY slot_no ASC
    """
    cursor.execute(query, (parking_id,))
    slots = cursor.fetchall()
    cursor.close()

    slot_list = [{
        'slot_no': s[0],
        'is_occupied': bool(s[1]),
        'vehicle_no': s[2],
        'entry_time': s[3].strftime("%Y-%m-%d %H:%M") if s[3] else None
    } for s in slots]

    return {'slots': slot_list}



@app.route('/admin/manage_users')
def manage_users():
    if 'user' in session and session.get('role') == 'admin':
        cursor = mysql.connection.cursor()

        # Get all users
        cursor.execute("SELECT user_id, role, name, email, is_verified FROM users")
        users = cursor.fetchall()

        # Fetch profiles
        cursor.execute("SELECT * FROM customer_profiles")
        profiles = cursor.fetchall()

        # Fetch payment info
        cursor.execute("SELECT * FROM payments")
        payments = cursor.fetchall()

        # Fetch bookings
        cursor.execute("SELECT * FROM bookings")
        bookings = cursor.fetchall()

        cursor.close()

        return render_template("manage_users.html", users=users, profiles=profiles, payments=payments, bookings=bookings)

    flash("Access denied.", "danger")
    return redirect(url_for("login"))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user' in session and session.get('role') == 'admin':
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        mysql.connection.commit()
        cursor.close()
        flash('User deleted successfully.', 'success')
        return redirect(url_for('manage_users'))

    flash('Access denied.', 'danger')
    return redirect(url_for('login'))



import csv
from io import StringIO
from flask import Response

@app.route('/admin/reports', methods=['GET', 'POST'])
def admin_reports():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    report_data = []
    report_type = request.form.get('report_type')
    filter_value = request.form.get('filter_value')

    cursor = mysql.connection.cursor()

    if request.method == 'POST' and report_type:
        if report_type == 'daily':
            query = """
                SELECT b.booking_id, u.name, b.parking_id, p.name as parking_name, 
                       b.entry_time, b.slot_no, r.vehicle_no, 
                       r.charges, IF(r.charges > 0, 'Paid', 'Pending') as payment_status
                FROM bookings b
                JOIN users u ON u.user_id = b.user_id
                JOIN parking_lots p ON p.parking_id = b.parking_id
                LEFT JOIN real_time_parking_info r ON r.parking_id = b.parking_id 
                    AND r.slot_no = b.slot_no 
                    AND r.entry_time = b.entry_time
                WHERE DATE(b.entry_time) = %s
                ORDER BY b.entry_time DESC
            """
            cursor.execute(query, (filter_value,))

        elif report_type == 'monthly':
            query = """
                SELECT b.booking_id, u.name, b.parking_id, p.name as parking_name,
                       b.entry_time, b.slot_no, r.vehicle_no,
                       r.charges, IF(r.charges > 0, 'Paid', 'Pending') as payment_status
                FROM bookings b
                JOIN users u ON u.user_id = b.user_id
                JOIN parking_lots p ON p.parking_id = b.parking_id
                LEFT JOIN real_time_parking_info r ON r.parking_id = b.parking_id 
                    AND r.slot_no = b.slot_no 
                    AND r.entry_time = b.entry_time
                WHERE MONTH(b.entry_time) = %s AND YEAR(b.entry_time) = %s
                ORDER BY b.entry_time DESC
            """
            month, year = filter_value.split('-')
            cursor.execute(query, (month, year))

        elif report_type == 'user':
            query = """
                SELECT b.booking_id, u.name, b.parking_id, p.name as parking_name,
                       b.entry_time, b.slot_no, r.vehicle_no,
                       r.charges, IF(r.charges > 0, 'Paid', 'Pending') as payment_status
                FROM bookings b
                JOIN users u ON u.user_id = b.user_id
                JOIN parking_lots p ON p.parking_id = b.parking_id
                LEFT JOIN real_time_parking_info r ON r.parking_id = b.parking_id 
                    AND r.slot_no = b.slot_no 
                    AND r.entry_time = b.entry_time
                WHERE u.email = %s
                ORDER BY b.entry_time DESC
            """
            cursor.execute(query, (filter_value,))

        report_data = cursor.fetchall()
        cursor.close()

        if 'download' in request.form:
            si = StringIO()
            cw = csv.writer(si)
            cw.writerow(['Booking ID', 'User Name', 'Parking ID', 'Parking Name', 
                         'Entry Time', 'Slot No', 'Vehicle No', 
                         'Amount', 'Payment Status'])
            for row in report_data:
                cw.writerow(row)
            output = si.getvalue()
            return Response(
                output,
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment;filename={report_type}_report.csv"}
            )

    return render_template('admin_reports.html', report_data=report_data)


















@app.route("/manager_login", methods=['GET', 'POST'])
def manager_login():
    if request.method == 'POST':
        parking_id = request.form['parking_id']
        parking_password = request.form['parking_password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT parking_password FROM parking_lots WHERE parking_id = %s", (parking_id,))
        result = cursor.fetchone()
        cursor.close()

        if result and result[0] == parking_password:
            session['parking_id'] = parking_id  # ✅ Store parking ID in session
            flash('Login successful!', 'success')
            return redirect(url_for('parking_manager_dashboard'))
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('parking_manager_login.html')


@app.route('/parking_manager_dashboard')
def parking_manager_dashboard():
    if 'parking_id' not in session:
        flash("Please login as parking manager.", "warning")
        return redirect(url_for('manager_login'))

    return render_template('parking_manager_dashboard.html')



@app.route('/manager/add_car', methods=['GET', 'POST'])
def add_car():
    if 'parking_id' not in session:
        flash("Please log in as a parking manager.", "warning")
        return redirect(url_for('manager_login'))

    parking_id = session['parking_id']

    if request.method == 'POST':
        vehicle_no = request.form.get('vehicle_no')
        exit_time = request.form.get('exit_time') or None
        entry_time = datetime.now()

        cursor = mysql.connection.cursor()

        # Find next available slot
        cursor.execute("""
            SELECT MIN(slot_no) FROM real_time_parking_info
            WHERE parking_id = %s AND is_occupied = 0
        """, (parking_id,))
        next_slot = cursor.fetchone()[0]

        if not next_slot:
            flash("No available slots at this moment.", "danger")
            return redirect(url_for('add_car'))

        # Insert car entry
        try:
            cursor.execute("""
                INSERT INTO real_time_parking_info 
                (parking_id, slot_no, is_occupied, vehicle_no, entry_time, exit_time, charges)
                VALUES (%s, %s, 1, %s, %s, %s, 0.00)
            """, (parking_id, next_slot, vehicle_no, entry_time, exit_time))
            mysql.connection.commit()
            flash("Car added successfully!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error adding car: {e}", "danger")
        finally:
            cursor.close()

        return redirect(url_for('manager_add_car'))

    return render_template("add_car.html", parking_id=parking_id)







@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


app.run(debug = True)