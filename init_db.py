from app import app, db, User, Candidate, bcrypt

def init_db():
    with app.app_context():
        # Drop all tables and create them again
        db.drop_all()
        db.create_all()

        # Create admin user
        admin = User(
            username='admin',
            email='admin@politian.com',
            password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            is_admin=True,
            cnic='00000-0000000-0',
            created_at=db.func.current_timestamp()
        )
        db.session.add(admin)

        # Add candidates
        candidates_data = [
            {
                'name': 'Imran Khan',
                'party': 'Pakistan Tehreek-e-Insaf',
                'image': 'imrankhan.jpg',
                'description': 'Former Prime Minister and Chairman of PTI'
            },
            {
                'name': 'Shehbaz Sharif',
                'party': 'Pakistan Muslim League (N)',
                'image': 'shehbaz.jpeg',
                'description': 'Former Prime Minister and President of PML-N'
            },
            {
                'name': 'Bilawal Bhutto',
                'party': 'Pakistan Peoples Party',
                'image': 'bilawal.jpeg',
                'description': 'Chairman of Pakistan Peoples Party'
            },
            {
                'name': 'Fazal-ur-Rehman',
                'party': 'Jamiat Ulema-e-Islam (F)',
                'image': 'fazal.jpeg',
                'description': 'Former Prime Minister and President of JUI-F'
            }
        ]

        for candidate_data in candidates_data:
            candidate = Candidate(**candidate_data)
            db.session.add(candidate)

        # Commit changes
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 