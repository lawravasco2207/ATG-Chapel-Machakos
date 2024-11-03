from flask import Flask, jsonify, render_template, redirect, url_for, flash, make_response, send_file, request
import psycopg2
import os
import io
import random
# from psycopg2 import sql
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, FileField, TextAreaField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange
from email_validator import validate_email, EmailNotValidError
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import PyPDF2
from fpdf import FPDF
import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.cron import CronTrigger
import requests
import smtplib
from flask_mail import Mail, Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# import turtle

app = Flask(__name__)
# kbwa fayc dqaz cxmc app password

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirects to login page if not logged in
login_manager.login_message_category = 'info'  # For flash messages


app.config['SECRET_KEY'] = 'mve38r53jx8ennd'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # Usually 587 for TLS
app.config['MAIL_USE_TLS'] = True  # Enable TLS
app.config['MAIL_USERNAME'] = 'atgdeliverancechapelmachakos@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'odwx dgfc husb fdrc'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = 'atgdeliverancechapelmachakos@gmail.com'  # Sender email

mail = Mail(app)

API_KEY = '8a33b90c0c768191d85c71ca9c523615'
BASE_URL = 'https://api.scripture.api.bible/v1/bibles'
BIBLE_ID = 'de4e12af7f28f599-02'  # example ID for English Standard Version
HEADERS = {'api-key': API_KEY}

# make sure the uploads folder is there 
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# PAGE_ID = '100091973706364'  # Example Page ID
# ACCESS_TOKEN = '8332130623552558|P5ZFX3UwjWsmc07Sb53CxWPZr0Q'  # Your generated access token


# Database configuration
DB_HOST = 'ep-crimson-paper-a59lkijq.us-east-2.aws.neon.tech'
DB_NAME = 'neondb'
DB_USER = 'neondb_owner'
DB_PASSWORD = 'cu1EAWBvCQU8'
# postgresql://Larry:4gkQNiC5lpOu@ep-crimson-paper-a59lkijq.us-east-2.aws.neon.tech/users?sslmode=require
# postgresql://neondb_owner:cu1EAWBvCQU8@ep-crimson-paper-a59lkijq.us-east-2.aws.neon.tech/neondb?sslmode=require
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn


def create_users_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL                
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

# call the function
create_users_table()


def create_notes_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id), -- assuming you have a users table
        content TEXT NOT NULL,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP 
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

# Call the function to ensure the table is created
create_notes_table()


def create_daily_verse_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS daily_verse (
            id SERIAL PRIMARY KEY,
            verse_content TEXT NOT NULL,
            date DATE NOT NULL,
            user_id INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

# Call the function to ensure the table is created
create_daily_verse_table()

def create_newsletter_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
            id SERIAL PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

# Call the function to ensure the table is created
create_newsletter_table()



class User(UserMixin):
    def __init__(self, id, username, email, admission_number=None):
        self.id = id
        self.username = username
        self.email = email

    # Additional methods can be definer = admission_numberd if needed


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        return User(id=user[0], username=user[1], email=user[2])
    return None


# signup form
class SignUp(FlaskForm):
      username = StringField("Username", validators=[DataRequired()])
      email = EmailField("Email", validators=[DataRequired(), Email()])
      password = PasswordField("Password", validators=[DataRequired()])
      confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
      submit = SubmitField("Create Account")

      def validate_email(self, field):
        try:
            # Validate email
            validate_email(field.data)
        except EmailNotValidError as e:
            raise ValueError(str(e))
        

# login form 
class Login(FlaskForm):
      username = StringField("Username", validators=[DataRequired()])
      password = PasswordField("Password", validators=[DataRequired()])
      submit = SubmitField("Login")

# notes form
class NotesForm(FlaskForm):
    content = TextAreaField("Write your note here", validators=[DataRequired()])
    submit = SubmitField("Save Note")


class AppointmentForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Book Appointment')


class EditVerseForm(FlaskForm):
    verse_content = TextAreaField('Edit Verse', validators=[DataRequired()])
    submit = SubmitField('Update Verse') 


class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired()])
    description = StringField('Event Description', validators=[DataRequired()])
    image = FileField('Event Image', validators=[DataRequired()])
    validity_duration = IntegerField('Validity Duration (in hours)', 
                                       validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Create Event')


# Newsletter subscription form
class NewsletterForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Subscribe")


@app.route('/')
@app.route('/index')
def index():
    # Fetch upcoming events from the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch events
    cur.execute("""SELECT title, description, image_path, created_at 
                   FROM events 
                   WHERE expiration_time > NOW() 
                   ORDER BY created_at DESC;""")
    events = cur.fetchall()

    cur.close()
    conn.close()

    # Render the index template with the events data
    return render_template('index.html', events=events)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)

        # Insert into the database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, password))
        conn.commit()
        cur.close()
        conn.close()

        flash('Sign up successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Query the database for user details
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, password FROM users WHERE username = %s",
            (username,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Check if the user exists, password is correct, and admission number matches
        if user and check_password_hash(user[3], password):
            logged_in_user = User(id=user[0], username=user[1], email=user[2])
            login_user(logged_in_user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard or home page
        else:
            flash('Login failed. Check your username, password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    form = NewsletterForm()
    if form.validate_on_submit():
        email = form.email.data
        
        # Flash a success message
        
        # Create and send the confirmation email
        msg = Message('Subscription Confirmation',
                      recipients=[email])  # Send to the subscriber's email
        msg.body = 'Thank you for subscribing to our newsletter!'
        
        try:
            mail.send(msg)
            flash('You have been successfully added to our newsletter!', 'success')
        except Exception as e:
            flash('There was an issue sending the confirmation email.', 'danger')
            print(e)  # Log the error

        # Redirect to a different page or render a template
        return redirect(url_for('index'))  # Adjust this to your home route

    return render_template('subscribe.html', form=form)


def send_newsletter(content):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM newsletter_subscribers")
    subscribers = cur.fetchall()
    
    # SMTP configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = current_user.email
    # sender_password = "odwx dgfc husb fdrc"  # Use an app password if using Gmail

    for subscriber in subscribers:
        recipient_email = subscriber[0]
        message = EmailMessage()
        message.set_content(content)
        message['Subject'] = 'Our Latest Newsletter'
        message['From'] = sender_email
        message['To'] = recipient_email

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            # server.login(sender_email, sender_password)
            server.send_message(message)

    cur.close()
    conn.close()


@app.route('/send_newsletter', methods=['POST'])
@login_required  # Ensure only logged-in users can send newsletters
def send_newsletter_route():
    content = request.form.get('content')  # Get content from the form
    send_newsletter(content)
    flash('Newsletter sent successfully!', 'success')
    return redirect(url_for('dashboard'))  # Redirect back to dashboard or any page



@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch the current user's details
    username = current_user.username
    email = current_user.email

    # Connect to the database
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Fetch the user's name
    cur.execute('SELECT username FROM users WHERE id = %s', (current_user.id,))
    name = cur.fetchone()[0]

    # Fetch the latest note created by the user
    cur.execute("""
        SELECT content, timestamp 
        FROM notes 
        WHERE user_id = %s 
        ORDER BY timestamp DESC 
        LIMIT 1
    """, (current_user.id,))
    last_note = cur.fetchone()  # This will be None if there are no notes

    # Fetch events related to the current user
    cur.execute("""
        SELECT title, description, image_path, created_at, expiration_time 
        FROM events 
        WHERE user_id = %s;
    """, (current_user.id,))
    events = cur.fetchall()

    # Fetch appointments related to the current user
    cur.execute("""
        SELECT id, subject, description, created_at 
        FROM appointments 
        WHERE user_id = %s;
    """, (current_user.id,))
    appointments = cur.fetchall()
    
    cur.close()
    conn.close()

    # Pass all data to the template
    return render_template(
        'dashboard.html', 
        username=username, 
        email=email, 
        name=name, 
        events=events, 
        appointments=appointments, 
        last_note=last_note
    )



@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    form = NotesForm()
    
    # Handle new note submission
    if form.validate_on_submit():
        content = form.content.data
        user_id = current_user.id
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO notes (user_id, content, timestamp) VALUES (%s, %s, %s)",
            (user_id, content, datetime.utcnow())
        )
        conn.commit()
        cur.close()
        conn.close()
        
        flash("Note saved successfully!", "success")
        return redirect(url_for('notes'))
    
    # Fetch user's notes from the database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, content, timestamp FROM notes WHERE user_id = %s ORDER BY timestamp DESC", (current_user.id,))
    notes = cur.fetchall()  # List of tuples (id, content, timestamp)
    cur.close()
    conn.close()
    
    return render_template('notes.html', form=form, notes=notes)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Note deleted successfully!", "info")
    return redirect(url_for('notes'))



@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/services')
def services():
    return render_template('services.html')


def get_books():
    url = f"{BASE_URL}/{BIBLE_ID}/books"
    response = requests.get(url, headers=HEADERS)
    return response.json()['data'] if response.status_code == 200 else []


def get_chapters(book_id):
    url = f"{BASE_URL}/{BIBLE_ID}/books/{book_id}/chapters"
    response = requests.get(url, headers=HEADERS)
    return response.json()['data'] if response.status_code == 200 else []

def get_verses(chapter_id):
    url = f"{BASE_URL}/{BIBLE_ID}/chapters/{chapter_id}/verses"
    response = requests.get(url, headers=HEADERS)
    return response.json()['data'] if response.status_code == 200 else []


def get_verse_text(verse_id):
    url = f"{BASE_URL}/{BIBLE_ID}/verses/{verse_id}"
    response = requests.get(url, headers=HEADERS)
    return response.json()['data']['content'] if response.status_code == 200 else "Verse not found."


def get_chapter_or_verse_range(chapter_id, start_verse_id=None, end_verse_id=None):
    if start_verse_id and end_verse_id:
        url = f"{BASE_URL}/{BIBLE_ID}/chapters/{chapter_id}/verses/{start_verse_id}..{end_verse_id}"
    else:
        url = f"{BASE_URL}/{BIBLE_ID}/chapters/{chapter_id}"  # Get the full chapter

    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()['data']['content']  # Adjust as needed for full chapter content
    return "Content not found."



@app.route('/bible', methods=['GET', 'POST'])
def bible():
    books = get_books()
    selected_text = ''
    if request.method == 'POST':
        book_id = request.form.get('book')
        chapter_id = request.form.get('chapter')
        start_verse_id = request.form.get('start_verse')
        end_verse_id = request.form.get('end_verse')
        
        if chapter_id:
            selected_text = get_chapter_or_verse_range(
                chapter_id,
                start_verse_id=start_verse_id,
                end_verse_id=end_verse_id
            )

    return render_template('bible_reader.html', books=books, selected_text=selected_text)


@app.route('/chapters/<book_id>', methods=['GET'])
def chapters(book_id):
    chapters = get_chapters(book_id)
    return jsonify(chapters)

@app.route('/verses/<chapter_id>', methods=['GET'])
def verses(chapter_id):
    verses = get_verses(chapter_id)
    return jsonify(verses)


@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    form = AppointmentForm()
    if form.validate_on_submit():
        subject = form.subject.data
        description = form.description.data
        user_id = current_user.id  # Get the user ID of the currently logged-in user

        # Insert the appointment into the database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO appointments (user_id, subject, description) VALUES (%s, %s, %s)",
            (user_id, subject, description)
        )
        conn.commit()
        cur.close()
        conn.close()

        # Send an email notification
        sender_email = current_user.email
        receiver_email = "atgdeliverancechapelmachakos@gmail.com"
        smtp_server = "smtp.gmail.com"
        port = 587

        # Create the email content
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
    
        msg["Subject"] = subject
        msg.attach(MIMEText(description, "plain"))

        # Send the email
        try:
            server = smtplib.SMTP(smtp_server, port)
            server.starttls()
            server.login("atgdeliverancechapelmachakos@gmail.com", "odwx dgfc husb fdrc")  # Replace with your actual credentials
            server.sendmail(sender_email, receiver_email, msg.as_string())
            server.quit()
            flash('Appointment booked successfully!', 'success')
        except Exception as e:
            flash("An error occurred while sending the email: " + str(e), "danger")

        return redirect(url_for('dashboard'))

    return render_template('book_appointment.html', form=form)


def update_daily_verse():
    # Replace with your preferred Bible API and authentication details
    bible_api_url = "https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-02/books"
    headers = {"api-key": API_KEY}

    # Fetch a random book from the Bible
    response = requests.get(bible_api_url, headers=headers)
    books = response.json()['data']
    random_book = random.choice(books)
    book_id = random_book['id']

    # Fetch a random chapter from the book
    chapters_url = f"https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-02/books/{book_id}/chapters"
    response = requests.get(chapters_url, headers=headers)
    chapters = response.json()['data']
    random_chapter = random.choice(chapters)
    chapter_id = random_chapter['id']

    # Fetch a random verse from the chapter
    verses_url = f"https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-02/chapters/{chapter_id}/verses"
    response = requests.get(verses_url, headers=headers)
    verses = response.json()['data']
    random_verse = random.choice(verses)
    verse_id = random_verse['id']

    # Fetch the verse content
    verse_url = f"https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-02/verses/{verse_id}"
    response = requests.get(verse_url, headers=headers)
    verse_content = response.json()['data']['content']

    # Store the verse in the database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO daily_verse (verse_content, book, chapter, verse, date) VALUES (%s, %s, %s, %s, %s)",
                (verse_content, random_book['name'], random_chapter['number'], random_verse['number'], datetime.today().date()))
    conn.commit()
    cur.close()
    conn.close()

# Schedule the update_daily_verse function to run at 4:00 AM Kenyan Time
sched = BackgroundScheduler(timezone='Africa/Nairobi')
sched.add_job(update_daily_verse, 'cron', hour=4)
sched.start()

@app.route('/daily_verse', methods=['GET', 'POST'])
@login_required
def daily_verse():
    # Fetch the daily verse from the database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT verse_content, book, chapter, verse FROM daily_verse WHERE date = %s", (datetime.today().date(),))
    daily_verse = cur.fetchone()
    cur.close()
    conn.close()

    # Check if daily verse exists and hasn't expired (24 hours)
    if daily_verse and datetime.now() - timedelta(days=1) < daily_verse[0]:
        verse_content, book, chapter, verse = daily_verse
        edit_enabled = current_user.email == "lawravasco@gmail.com" and datetime.now().hour < 5  # Edit disabled after 5 AM
    else:
        verse_content = "There is no daily verse yet or it has expired."
        book = None
        chapter = None
        verse = None
        edit_enabled = False

    # Edit form (only displayed if email matches and before 5 AM)
    edit_form = None
    if edit_enabled:
        edit_form = EditVerseForm()
        if edit_form.validate_on_submit():
            new_verse_content = edit_form.verse_content.data
            # Update the verse content in the database
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE daily_verse SET verse_content = %s WHERE date = %s", (new_verse_content, datetime.today().date()))
            conn.commit()
            cur.close()
            conn.close()
            flash("Daily verse updated successfully!")
            return redirect(url_for('daily_verse'))

    return render_template('daily_verse.html', verse_content=verse_content, book=book, chapter=chapter, verse=verse, edit_form=edit_form, edit_enabled=edit_enabled)


# Daily verse context processor
@app.context_processor
def inject_daily_verse():
    # Fetch today's daily verse from the database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT verse_content FROM daily_verse WHERE date = %s", (datetime.today().date(),))
    daily_verse = cur.fetchone()
    cur.close()
    conn.close()

    # Set default message if no daily verse is found
    verse_content = daily_verse[0] if daily_verse else "No daily verse available."

    return {'daily_verse_content': verse_content}


@app.route('/add_event', methods=['GET', 'POST'])
@login_required
def add_event():
    form = EventForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        image = form.image.data
        validity_duration = form.validity_duration.data

        # Check if the file is in the allowed format
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the image
            image.save(image_path)

            # Insert the event into the database
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO events (user_id, title, description, image_path, expiration_time) VALUES (%s, %s, %s, %s, NOW() + INTERVAL %s DAY)",
                (current_user.id, title, description, image_path, validity_duration)
            )
            conn.commit()
            cur.close()
            conn.close()

            flash('Event added successfully!', 'success')
            return redirect(url_for('index'))

        else:
            flash('Invalid image format. Please upload a .png, .jpg, .jpeg, or .gif file.', 'danger')

    return render_template('add_event.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
