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

## Project Visuals

![Home Page](https://github.com/user-attachments/assets/d36c2d9c-171f-4c31-ad93-bd6d4706f2d2)
![Home Page 2](https://github.com/user-attachments/assets/872ac256-9c8c-4f47-92f3-0c6f3d1d1a49)
![Home Page 3](https://github.com/user-attachments/assets/7af0d71a-1082-4fdd-b4eb-3c1b25622a6e)
![Compaign Page](https://github.com/user-attachments/assets/01d97ba5-0da8-4637-97b6-a37d180c9816)
![Voter Registration Page](https://github.com/user-attachments/assets/a0a94693-9f50-4fc2-9ba6-a3250b726374)
![Voter Login Page](https://github.com/user-attachments/assets/35583ca3-4303-44a6-8f0b-4f60152ef9ca)
![Admin Login Page](https://github.com/user-attachments/assets/44b56f2b-5826-4568-b443-10d3a5fa1bfe)
![Voting Statistics](https://github.com/user-attachments/assets/623d9d16-41ee-4ab3-a517-f12cab2dd6f2)
![User Management](https://github.com/user-attachments/assets/63fb8b55-213a-48b1-a2a0-95abc41dc7d0)
![Analytics Page](https://github.com/user-attachments/assets/fae3acee-c93b-4006-bb6b-0e6fbde7221d)
![User Activity](https://github.com/user-attachments/assets/31bf4363-e139-47cf-afe5-39510f40fec8)
![Real-Time Monitoring](https://github.com/user-attachments/assets/0686d79f-3d89-499f-b0ac-32c5b9c0eb4b)
![Audit Logs](https://github.com/user-attachments/assets/23db6aab-d534-454c-9a0b-fc4a3c04a4c1)
![Audit Logs 2](https://github.com/user-attachments/assets/3dd34cee-b142-4b77-8139-4c4cff8e32bc)
















## License

This project is licensed under the MIT License - see the LICENSE file for details. 
