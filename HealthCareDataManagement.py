from flask import Flask, request, render_template, jsonify, make_response,session, redirect, url_for, flash
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import pickle
from datetime import datetime, timedelta
import mysql.connector,json
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from functools import wraps

app = Flask(__name__)
oauth = OAuth(app)
API_URL = "https://api.worqhat.com/api/ai/content/v2"
API_TOKEN = "sk-4553c2378af54b33bf8986dfdae6092c"
# Disable caching for static files
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
# Google Calendar API scopes
scopes = ['https://www.googleapis.com/auth/calendar']

app.secret_key = 'Amazon'  # set a secret key for session management
cnx = mysql.connector.connect(
    user='root',
    password='root2003',
    host='healthcare-management.cr2uy460cuky.us-east-1.rds.amazonaws.com',
    database='healthcare_management'
)

# Create a cursor object to execute SQL queries
cursor = cnx.cursor()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=50)

cnt = 0  # Declare cnt outside of the route function

# Define a decorator function to check authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # flash('You must be logged in to access this page.', 'error')
            # Use a JavaScript alert and then redirect
            return f'''
            <script>
                alert('Login is required !!');
                window.location.href = '/login';
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function
# Define routes for signup and login

@app.route('/signup', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        email = request.form['email']
        contact_number = request.form['contact_number']
        hashed_password = generate_password_hash(password)

        # Check if the email already exists in the database
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return '''
            <script>
                alert('Email already exists !!');
                window.location.href = '/signup';
            </script>
            '''

        # Insert the new user into the users table with role 'Patient'
        insert_query = "INSERT INTO users (first_name, last_name, email, password_hash, role, contact_number) VALUES (%s, %s, %s, %s, %s, %s)"
        insert_data = (first_name, last_name, email, hashed_password, 'Patient', contact_number)
        cursor.execute(insert_query, insert_data)
        cnx.commit()

        subject = "Welcome to Healthcare Management System"
        message = f"Thank you {first_name} {last_name} for registering with our Healthcare Management System."
        send_email(email, subject, message)

        # Add the user details to the session
        session['user_id'] = cursor.lastrowid
        session['first_name'] = first_name
        session['last_name'] = last_name
        session['email'] = email
        session['role'] = 'Patient'

        return redirect(url_for('patient_home'))  # Redirect to the patient's home page after signup

    return render_template('signup.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login_user():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']

#         # Query the database to find the user by email
#         cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
#         user = cursor.fetchone()

#         if user and check_password_hash(user[4], password):  # Check password hash
#             # Add user details to the session
#             session['doctor_id'] = user[0]
#             session['username'] = user[1]
#             session['last_name'] = user[2]
#             session['email'] = user[3]
#             session['role'] = user[5]

#             # Redirect based on role
#             if user[5] == 'Patient':
#                 return redirect(url_for('patient_home'))
#             elif user[5] == 'Doctor':
#                 return redirect(url_for('doctor_home'))
#             elif user[5] == 'Medical Staff':
#                 return redirect(url_for('medical_staff_home'))
#         else:
#             return '''
#             <script>
#                 alert('Invalid email or password');
#                 window.location.href = '/login';
#             </script>
#             '''

#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email=='admin' and password=='admin':
            return render_template('admin_dashboard.html')
        try:
            # Query the database to find the user by email
            cursor.execute("SELECT username, password_hash FROM login WHERE username = %s", (email,))
            user = cursor.fetchone()
            cnx.commit()
            if user and check_password_hash(user[1], password):  # Check password hash
                # Query the database to get doctor_id from doctors table
                cursor.execute("SELECT doctor_id FROM doctors WHERE email = %s", (email,))
                doctor = cursor.fetchone()

                if doctor:
                    # Add user details and doctor_id to the session
                    session['username'] = user[0]
                    session['doctor_id'] = doctor[0]
                    return render_template("index.html")  # Replace with the actual route for the dashboard
                else:
                    return redirect(url_for('login'))
            else:
                return redirect(url_for('login'))

        except Exception as e:
            print(f"Error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Home routes for different roles

@app.route('/patient_home')
@login_required
def patient_home():
    username = session.get('username')
    return render_template('patient.html',username=username)

@app.route('/help')
def ChatBot():
    return render_template('help.html')

@app.route('/dhelp')
@login_required
def DoctorsChatBot():
    return render_template('doctorhelp.html')

@app.route('/patients_view', methods=['GET'])
@login_required
def patient_view():
    doctor_id = session.get('doctor_id')
    if doctor_id:
        query = '''
            SELECT DISTINCT p.patient_id, p.first_name, p.last_name, p.email, p.age, p.address, p.phone_number
            FROM patients p
            INNER JOIN reports r ON p.patient_id = r.patient_id
            WHERE r.doctor_id = %s
        '''
        cursor.execute(query, (doctor_id,))
        patients = cursor.fetchall()

        patient_data = []
        for patient in patients:
            patient_dict = {
                'patient_id': patient[0],
                'first_name': patient[1],
                'last_name': patient[2],
                'email': patient[3],
                'age': patient[4],
                'address': patient[5],
                'phone_number': patient[6]
            }
            patient_data.append(patient_dict)

        return render_template('patient_view.html', patient_data=patient_data)

@app.route('/departments_view', methods=['GET'])
def departments_view():
    query = '''
        SELECT * FROM departments
    '''
    cursor.execute(query)
    departments = cursor.fetchall()

    department_data = []
    for department in departments:
        department_dict = {
            'department_id': department[0],
            'name': department[1],
            'description': department[2],
            'num_doctors': department[3],
            'num_nurses': department[4],
            'cases_handled': department[5]
        }
        department_data.append(department_dict)

    return render_template('departments_view.html', departments=department_data)

@app.route('/reports', methods=['GET'])
@login_required
def reports_view():
    doctor_id = session.get('doctor_id')
    if doctor_id:
        query = '''
            SELECT r.report_id, r.patient_id, p.first_name, p.last_name, r.disease, r.cure, r.date_admitted, r.date_discharged, r.symptoms
            FROM reports r
            INNER JOIN patients p ON r.patient_id = p.patient_id
            WHERE r.doctor_id = %s
        '''
        cursor.execute(query, (doctor_id,))
        reports = cursor.fetchall()

        report_data = []
        for report in reports:
            report_dict = {
                'report_id': report[0],
                'patient_id': report[1],
                'patient_name': f"{report[2]} {report[3]}",
                'disease': report[4],
                'cure': report[5],
                'date_admitted': report[6],
                'date_discharged': report[7],
                'symptoms': report[8]
            }
            report_data.append(report_dict)

        return render_template('reports_view.html', report_data=report_data)

@app.route('/appointments')
@login_required
def Appointments_Show():
    username = session.get('username')
    return render_template('appointments.html',username=username)

@app.route('/admin')
def Admin_Dashboard():
    return render_template('admin_dashboard.html')

@app.route('/register_patient')
@login_required
def Patient_Registration():
    username = session.get('username')
    return render_template('register_patient.html',username=username)

@app.route('/doctor_home')
@login_required
def doctor_home():
    # Add code for doctor's home page
    return render_template('index.html')

@app.route('/medical_staff_home')
def medical_staff_home():
    # Add code for medical staff's home page
    return "Welcome to the Medical Staff Home Page"

#New Routes

@app.route('/search_patient', methods=['POST'])
def search_patient():
    search_query = request.form['search']
    print("Name: "+search_query)
    cursor.execute("SELECT * FROM patients WHERE first_name LIKE %s OR last_name LIKE %s", (f"%{search_query}%", f"%{search_query}%"))
    patient = cursor.fetchone()
    if patient:
        patient_data = {
            'patient_id': patient[0],
            'first_name': patient[1],
            'last_name': patient[2],
            'email': patient[3],
            'age': patient[4],
            'address': patient[5],
            'phone_number': patient[6]
        }
    else:
        patient_data = None

    return render_template('appointments.html',patient=patient_data)
@app.route('/add_report', methods=['POST'])
def add_report():
    patient_id = request.form['patient_id']
    disease = request.form['disease']
    cure = request.form['cure']
    date_admitted = request.form['date_admitted']
    date_discharged = request.form['date_discharged']
    symptoms = request.form['symptoms']
    doctor_id = session.get('doctor_id')
    print(doctor_id)

    # Insert the report into the reports table
    insert_report_query = """
    INSERT INTO reports (patient_id, doctor_id, disease, cure, date_admitted, date_discharged, symptoms)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    insert_report_data = (patient_id, doctor_id, disease, cure, date_admitted, date_discharged, symptoms)
    cursor.execute(insert_report_query, insert_report_data)

    # Update the cases_handled for the doctor
    update_doctor_query = """
    UPDATE doctors
    SET cases_handled = cases_handled + 1
    WHERE doctor_id = %s
    """
    cursor.execute(update_doctor_query, (doctor_id,))

    # Fetch the department_id of the doctor
    get_department_query = """
    SELECT department_id
    FROM doctors
    WHERE doctor_id = %s
    """
    cursor.execute(get_department_query, (doctor_id,))
    result = cursor.fetchone()
    department_id = result[0]

    # Update the cases_handled for the department
    update_department_query = """
    UPDATE departments
    SET cases_handled = cases_handled + 1
    WHERE department_id = %s
    """
    cursor.execute(update_department_query, (department_id,))

    # Fetch the patient's email address
    get_patient_email_query = """
    SELECT email
    FROM patients
    WHERE patient_id = %s
    """
    cursor.execute(get_patient_email_query, (patient_id,))
    result = cursor.fetchone()
    patient_email = result[0]

    # Commit the changes to the database
    cnx.commit()

    # Send the email to the patient
    subject = "Medical Report"
    message = f"Dear Patient,\n\nYour medical report has been generated.\n\nDisease: {disease}\nCure: {cure}\nDate Admitted: {date_admitted}\nDate Discharged: {date_discharged}\nSymptoms: {symptoms}\n\nBest Regards,\nYour Hospital Team"
    email_thread = threading.Thread(target=send_email, args=(patient_email, subject, message))
    email_thread.start()

    return '''
            <script>
                alert('Report successfully sent!!');
                window.location.href = '/appointments';
            </script>
            '''

from werkzeug.security import generate_password_hash

@app.route('/add_doctor', methods=['GET', 'POST'])
def add_doctor():
    if request.method == 'POST':
        # Retrieve form data
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        age = request.form['age']
        address = request.form['address']
        phone_number = request.form['phone_number']
        experience = request.form['experience']
        department_id = request.form['department_id']
        position = request.form['position']
        date_of_joining = request.form['date_of_joining']
        salary = request.form['salary']

        # Hash the password
        hashed_password = generate_password_hash(password)

        try:
            # Insert doctor's login credentials into the login table
            insert_login_query = """
            INSERT INTO login (username, password_hash)
            VALUES (%s, %s)
            """
            cursor.execute(insert_login_query, (email, hashed_password))

            # Insert doctor's details into the doctors table
            insert_doctor_query = """
            INSERT INTO doctors (
                first_name, last_name, email, age, address, phone_number,
                experience, department_id, position, date_of_joining, salary
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            doctor_data = (
                first_name, last_name, email, age, address, phone_number,
                experience, department_id, position, date_of_joining, salary
            )
            cursor.execute(insert_doctor_query, doctor_data)

            # Update the number of doctors in the department
            update_department_query = """
            UPDATE departments
            SET num_doctors = num_doctors + 1
            WHERE department_id = %s
            """
            cursor.execute(update_department_query, (department_id,))

            # Commit the changes to the database
            cnx.commit()

            return '''
                <script>
                    alert('Doctor added successfully!');
                    window.location.href = '/manage_doctors';
                </script>
            '''
        except Exception as e:
            # Rollback the transaction if an error occurs
            cnx.rollback()
            # Print the error for debugging
            print(f"Error: {e}")
            return f'''
                <script>
                    alert('An error occurred while adding the doctor: {e}');
                    window.location.href = '/add_doctor';
                </script>
            '''
    else:
        try:
            # Fetch departments from the database
            fetch_departments_query = "SELECT department_id, name FROM departments"
            cursor.execute(fetch_departments_query)
            departments = cursor.fetchall()

            # Print departments for debugging
            print("Fetched Departments:", departments)

            return render_template('add_doctor.html', departments=departments)
        except Exception as e:
            # Print the error for debugging
            print(f"Error fetching departments: {e}")
            return '''
                <script>
                    alert('An error occurred while fetching departments. Please try again.');
                    window.location.href = '/add_doctor';
                </script>
            '''





@app.route('/register_patient', methods=['POST'])
def register_patient():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    age = request.form['age']
    address = request.form['address']
    phone_number = request.form['phone_number']

    # Check if the patient already exists
    check_patient_query = """
    SELECT * FROM patients
    WHERE email = %s
    """
    cursor.execute(check_patient_query, (email,))
    existing_patient = cursor.fetchone()

    if existing_patient:
        # Patient already exists, redirect back to the registration form
        return '''
            <script>
                alert('Patient Already Exists!!');
                window.location.href = '/register_patient';
            </script>
            '''
    else:
        # Insert the new patient into the database
        insert_patient_query = """
        INSERT INTO patients (first_name, last_name, email, age, address, phone_number)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        insert_patient_data = (first_name, last_name, email, age, address, phone_number)
        cursor.execute(insert_patient_query, insert_patient_data)
        cnx.commit()

        # Redirect to the appointments page after successful registration
        return '''
            <script>
                alert('Patient Successfully Registerd!!');
                window.location.href = '/appointments';
            </script>
            '''

@app.route('/manage_doctors', methods=['GET'])
def manage_doctors():
    try:
        # Fetch all doctors from the database
        fetch_doctors_query = "SELECT doctor_id, first_name, last_name, email, phone_number, department_id, position, date_of_joining, salary FROM doctors"
        cursor.execute(fetch_doctors_query)
        doctors = cursor.fetchall()
        
        # Fetch department names for each doctor
        fetch_departments_query = "SELECT department_id, name FROM departments"
        cursor.execute(fetch_departments_query)
        departments = cursor.fetchall()
        department_dict = {department[0]: department[1] for department in departments}
        cnx.commit()
        # Adding department names to doctors
        doctors_with_dept_names = [
            doctor + (department_dict.get(doctor[5], 'Unknown'),)
            for doctor in doctors
        ]
        
        return render_template('manage_doctors.html', doctors=doctors_with_dept_names)
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while fetching doctors. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

#### DELETE Method to Delete a Doctor
@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    try:
        
        # Get the department_id and email of the doctor to update the num_doctors count later
        get_doctor_info_query = "SELECT department_id, email FROM doctors WHERE doctor_id = %s"
        cursor.execute(get_doctor_info_query, (doctor_id,))
        result = cursor.fetchone()
        if not result:
            raise Exception("Doctor not found.")
        department_id, email = result
        
        # Delete all reports associated with the doctor
        delete_reports_query = "DELETE FROM reports WHERE doctor_id = %s"
        cursor.execute(delete_reports_query, (doctor_id,))
        
        # Decrement the num_doctors count in the department
        update_department_query = "UPDATE departments SET num_doctors = num_doctors - 1 WHERE department_id = %s"
        cursor.execute(update_department_query, (department_id,))
        
        # Delete the doctor from the doctors table
        delete_doctor_query = "DELETE FROM doctors WHERE doctor_id = %s"
        cursor.execute(delete_doctor_query, (doctor_id,))
        
        # Delete the doctor's login credentials from the login table
        delete_login_query = "DELETE FROM login WHERE username = %s"
        cursor.execute(delete_login_query, (email,))
        
        # Commit the transaction
        cnx.commit()

        return '''
            <script>
                alert('Doctor Deleted Successfully!!');
                window.location.href = '/manage_doctors';
            </script>
        '''
    except Exception as e:
        print(f"Error: {e}")
        cnx.rollback()
        return '''
            <script>
                alert('Error Deleting!!');
                window.location.href = '/manage_doctors';
            </script>
        '''



@app.route('/logout',methods=['GET', 'POST'])
def logout_user():
    session.pop('doctor_id', None)  # Remove username from the session
    session.pop('username',None)    
    return render_template("login.html")  # Redirect to login page after logout

#edit by shubhan
@app.route('/manage_nurses', methods=['GET'])
def manage_nurses():
    try:
        # Fetch all nurses from the database
        fetch_nurses_query = "SELECT nurse_id, first_name, last_name, email, phone_number, date_of_joining, salary, department_id FROM nurses"
        cursor.execute(fetch_nurses_query)
        nurses = cursor.fetchall()

        # Fetch department names for each nurse
        fetch_departments_query = "SELECT department_id, name FROM departments"
        cursor.execute(fetch_departments_query)
        departments = cursor.fetchall()
        cnx.commit()
        department_dict = {department[0]: department[1] for department in departments}

        # Adding department names to nurses
        nurses_with_dept_names = [
            nurse + (department_dict.get(nurse[7], 'Unknown'),)
            for nurse in nurses
        ]

        return render_template('manage_nurses.html', nurses=nurses_with_dept_names)
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while fetching nurses. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete_nurse/<int:nurse_id>', methods=['POST'])
def delete_nurse(nurse_id):
    try:

        # Retrieve the department_id of the nurse to update the num_nurses count later
        get_department_query = "SELECT department_id FROM nurses WHERE nurse_id = %s"
        cursor.execute(get_department_query, (nurse_id,))
        result = cursor.fetchone()
        if not result:
            raise Exception("Nurse not found.")
        department_id = result[0]

        # Delete the nurse from the database
        delete_nurse_query = "DELETE FROM nurses WHERE nurse_id = %s"
        cursor.execute(delete_nurse_query, (nurse_id,))

        # Decrease the num_nurses count in the department
        update_department_query = "UPDATE departments SET num_nurses = num_nurses - 1 WHERE department_id = %s"
        cursor.execute(update_department_query, (department_id,))

        # Commit the transaction
        cnx.commit()

        return '''
            <script>
                alert('Nurse Deleted Successfully!!');
                window.location.href = '/manage_nurses';
            </script>
        '''
    except Exception as e:
        print(f"Error: {e}")
        cnx.rollback()
        return '''
            <script>
                alert('Error Deleting!!');
                window.location.href = '/manage_nurses';
            </script>
        '''


@app.route('/add_nurse', methods=['GET', 'POST'])
def add_nurse():
    fetch_departments_query = "SELECT department_id, name FROM departments"
    cursor.execute(fetch_departments_query)
    departments = cursor.fetchall()
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        age = request.form['age'] if request.form['age'] else None
        address = request.form['address']
        phone_number = request.form['phone_number']
        department_id = request.form['department_id']
        date_of_joining = request.form['date_of_joining']
        salary = request.form['salary'] if request.form['salary'] else None

        try:
            # Insert nurse into the nurses table
            insert_nurse_query = """
                INSERT INTO nurses (first_name, last_name, email, age, address, phone_number, department_id, date_of_joining, salary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (first_name, last_name, email, age, address, phone_number, department_id, date_of_joining, salary)
            cursor.execute(insert_nurse_query, values)
            
            # Update the num_nurses count in the departments table
            update_department_query = """
                UPDATE departments
                SET num_nurses = num_nurses + 1
                WHERE department_id = %s
            """
            cursor.execute(update_department_query, (department_id,))
            
            # Commit the changes to the database
            cnx.commit()
            
            return '''
                <script>
                    alert('Nurse added successfully!');
                    window.location.href = '/manage_nurses';
                </script>
            '''
        except Exception as e:
            print(f"Error: {e}")
            cnx.rollback()
            flash('An error occurred while adding the nurse. Please try again.', 'danger')

    return render_template('add_nurse.html', departments=departments)


@app.route('/add_department', methods=['GET', 'POST'])
def add_department():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        try:
            insert_department_query = """
                INSERT INTO departments (name, description)
                VALUES (%s, %s)
            """
            values = (name, description)
            cursor.execute(insert_department_query, values)
            cnx.commit()
            return '''
                <script>
                    alert('Department added successfully!');
                    window.location.href = '/add_department';
                </script>
            '''
        except Exception as e:
            print(f"Error: {e}")
            cnx.rollback()
            return '''
                <script>
                    alert('Error Adding Department!');
                    window.location.href = '/add_department';
                </script>
            '''
    return render_template('add_department.html')


#ChatBot Code
import requests
@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')
    
    payload = {
        "question": user_message,
        "preserve_history": True,
        "randomness": 0.5,
        "stream_data": False,
        "conversation_history": [],
        "training_data": "You are CareBot and will be helping Doctors and medical staff of Hospital for any relevant information and you are made and designed by Aditya Dhanwai.",
        "response_type": "text"
    }
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(API_URL, json=payload, headers=headers)
    response_json = response.json()
    
    print(response_json)
    # Extract the answer from the content field in the response
    bot_answer = response_json.get('content', 'I am not sure how to respond to that.')

    return jsonify({'answer': bot_answer})

@app.route('/google/')
def google():

    GOOGLE_CLIENT_ID = ''
    GOOGLE_CLIENT_SECRET = ''

    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

     # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    print(redirect_uri)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

import random
@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    
    # Convert user dictionary to a proper format
    user_data = {
        'name': user.get('name'),
        'email': user.get('email'),
        # Add other relevant fields as needed
    }

    session['user'] = user_data
    session['username'] = user_data['name']  # Assuming 'name' is the username
    session['email'] = user_data['email']  # Store email in session
    print(" Google User ", user_data)
    
    # Check if the username already exists in the database
    cursor.execute("SELECT * FROM USERS WHERE username = %s", (user_data['name'],))
    existing_user = cursor.fetchone()

    if not existing_user:  # If username does not exist, insert the user into the database
        # Generate a random password (you may need to adjust this logic)
        random_password = generate_password_hash(str(random.randint(100000, 999999)))
        
        # Set default value for the number field
        default_number = '9421636870'
        
        # Insert the user's information into the USERS table
        cursor.execute("INSERT INTO USERS (username, email, password, number) VALUES (%s, %s, %s, %s)",
                       (user_data['name'], user_data['email'], random_password, default_number))
        cnx.commit()  # Commit the transaction

    return '''
    <script>
        alert('Sign in Successful from Google!!');
        window.location.href = '/';
    </script>
    '''
   
#SMTP Part
import smtplib
import threading
from datetime import timedelta
# Gmail SMTP settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "aditya.dhanwai@mitaoe.ac.in"
SMTP_PASSWORD = "nanb kpcl waae bfqn"
# Email account credentials
email_address = "aditya.dhanwai@mitaoe.ac.in"
password = "nanb kpcl waae bfqn"
def send_email(recipient, subject, message):
    try:
        print(recipient)
        # Connect to the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)

        # Compose the email
        email_message = f"Subject: {subject}\n\n{message}"
        server.sendmail(SMTP_USERNAME, recipient, email_message)

        server.quit()

        # Return a success message when the email is successfully sent
        return "Email sent successfully."
    except smtplib.SMTPException as e:
        error_message = f'Email could not be sent. SMTP Error: {str(e)}'
        print(error_message)
        return error_message
    except Exception as e:
        error_message = f'Email could not be sent. Error: {str(e)}'
        print(error_message)
        return error_message

if __name__ == '__main__':
    app.run(debug=True)
