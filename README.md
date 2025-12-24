\# CRYPT's Secure – Web Application



A secure Flask-based web application that demonstrates modern authentication, encryption, and secure coding practices for a cyber security major project.



\## Features



\- User registration and login with \*\*hashed passwords\*\* (PBKDF2-SHA256).

\- Session-based authentication using \*\*Flask-Login\*\*.

\- Database layer with \*\*Flask‑SQLAlchemy\*\*.

\- CSRF-protected forms using \*\*Flask‑WTF\*\*.

\- Basic protections against \*\*XSS\*\* and \*\*SQL injection\*\*.

\- Aurora-style CRYPT’s dashboard UI with modern gradients.



\## Tech Stack



\- Python 3.14

\- Flask 3.x

\- Flask-Login

\- Flask-WTF

\- Flask-SQLAlchemy

\- SQLite (development database)

\- HTML5, CSS3, Jinja2 templates



\## Local Setup



1\. \*\*Clone the repository\*\*



git clone https://github.com/crypt-zubair/secure-web-app.git

cd secure-web-app



text



2\. \*\*Install dependencies\*\*



Make sure `py` points to Python 3.14.



py -m pip install -r requirements.txt



text



> If `requirements.txt` is missing, install manually:

>

> ```

> py -m pip install flask flask-login flask-wtf flask-sqlalchemy

> ```



3\. \*\*Run the application\*\*



py -3.14 app.py



text



4\. \*\*Open in browser\*\*



Navigate to:



http://127.0.0.1:5000



text



\## Project Structure



secure-web-app/

├── app.py # Flask application entry point

├── models.py # SQLAlchemy models (User etc.)

├── forms.py # WTForms / Flask-WTF form classes

├── requirements.txt # Python dependencies

├── static/ # CSS, JS, images

│ ├── css/

│ └── js/

└── templates/ # Jinja2 templates

├── base.html

├── landing.html

├── login.html

└── dashboard.html



text



\## Security Highlights



\- Passwords are never stored in plain text.

\- CSRF tokens on all sensitive forms.

\- ORM queries to minimize SQL injection risk.

\- Auto-escaping templates to reduce XSS risk.



---



This project was developed as a \*\*Cyber Security major project\*\* to showcase secure web development practices under the CRYPT’s branding.

