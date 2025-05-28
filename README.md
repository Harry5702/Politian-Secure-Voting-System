# Politian - Secure Voting System

A secure and transparent voting platform built with Flask, featuring user authentication, real-time vote tracking, and an admin panel.

## Features

- User Registration and Authentication
- Secure Voting System
- Real-time Vote Tracking
- Admin Panel with Statistics
- Responsive Design
- Campaign Information
- Contact Form

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/politian.git
cd politian
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Initialize the database:
```bash
python init_db.py
```

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Default Admin Account

- Username: admin
- Password: admin123

## Project Structure

```
politian/
├── app.py
├── init_db.py
├── requirements.txt
├── README.md
├── static/
│   ├── css/
│   │   └── style.css
│   └── images/
│       ├── logo.png
│       ├── hero-image.jpeg
│       └── candidates/
└── templates/
    ├── base.html
    ├── home.html
    ├── campaign.html
    ├── vote.html
    ├── contact.html
    ├── login.html
    ├── register.html
    └── admin.html
```

## Security Features

- Password Hashing
- CSRF Protection
- Session Management
- SQL Injection Prevention
- XSS Protection

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 