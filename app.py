from flask import Flask, render_template, request, redirect, session
import mysql.connector
from mysql.connector import Error, pooling
from werkzeug.security import check_password_hash

app = Flask(__name__, template_folder='login-page')

app.secret_key = 'your_strong_secret_key'

dbconfig = {
    "host": "localhost",
    "user": "root",
    "password": "itzmelokesh18",
    "database": "Lokii_games"
}

try:
    connection_pool = mysql.connector.pooling.MySQLConnectionPool(
        pool_name="mypool",
        pool_size=5,
        **dbconfig
    )
except mysql.connector.Error as err:
    print(f"Error while connecting to MySQL: {err}")

def get_connection():
    return connection_pool.get_connection()

# Function to execute queries
def execute_query(query, data=None):
    connection = get_connection()
    cursor = connection.cursor()
    try:
        if data:
            cursor.execute(query, data)
        else:
            cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")
    finally:
        cursor.close()
        connection.close()

# Route for index page (initial page)
@app.route('/')
def index():
    message = session.pop('message', None)  # Get and clear message from session
    return render_template('index.html', message=message)

# Route for signup
@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    
    check_user_query = "SELECT * FROM users WHERE email = %s"
    user_data = (email,)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(check_user_query, user_data)
    user = cursor.fetchone()

    if user:
        session['message'] = "User already exists. Please log in."
        cursor.close()
        connection.close()
        return redirect('/')
    
    insert_user_query = """
    INSERT INTO users (name, email, password)
    VALUES (%s, %s, %s)
    """
    user_data = (name, email, password)  # Store password directly
    execute_query(insert_user_query, user_data)
    
    cursor.close()
    connection.close()
    return redirect('/')

# Route for login
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    login_query = "SELECT * FROM users WHERE email = %s"
    login_data = (email,)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(login_query, login_data)
    user = cursor.fetchone()

    if user and user[3] == password:  # Assuming user[3] is the password column
        session['user'] = user
        cursor.close()
        connection.close()
        return redirect('/welcome')
    else:
        session['message'] = "Incorrect email or password. Please try again."
        cursor.close()
        connection.close()
        return redirect('/')

# Route for resetting password
@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form['email']
    name = request.form['name']
    new_password = request.form['new_password']

    # Check if the email and name combination exists in the database
    check_user_query = "SELECT * FROM users WHERE email = %s AND name = %s"
    user_data = (email, name)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(check_user_query, user_data)
    user = cursor.fetchone()

    if user:
        # Update the password with new plain text password
        update_password_query = "UPDATE users SET password = %s WHERE email = %s"
        update_data = (new_password, email)
        execute_query(update_password_query, update_data)

        session['message'] = "Password reset successfully. Please login with your new password."
    else:
        session['message'] = "Email or Name does not match. Please try again."

    cursor.close()
    connection.close()
    return redirect('/')

# Route for welcome page
@app.route('/welcome')
def welcome():
    if 'user' in session:
        user = session['user']
        username = user[1]  # Assuming user[1] is the column index for username
        # Redirect to external link passing username as parameter
        return redirect(f'https://nellurilokesh.github.io/games_interfaces/?username={username}')
    else:
        return redirect('/login')

# Route for logout
@app.route('/logout')
def logout():
    session.pop('user', None)  # Clear user session data
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
