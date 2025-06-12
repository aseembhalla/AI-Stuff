# API Key Manager

A web application for managing API keys with Stripe payment integration.

## Features

- Google OAuth authentication
- API key generation with Stripe payment
- API key management dashboard
- Key expiration tracking
- Key renewal functionality
- Copy to clipboard functionality
- Success/failure notifications

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file with your configuration:

Copy the `.env.example` file to `.env` and update the values:
```bash
cp .env.example .env
```

Then edit the `.env` file and update the following values:

- `SECRET_KEY`: Generate a secure random string (use `python -c "import secrets; print(secrets.token_hex(32))"`)
- `DATABASE_URL`: Update with your PostgreSQL connection string
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: Get these from Google Cloud Console
- `STRIPE_SECRET_KEY` and `STRIPE_PUBLIC_KEY`: Get these from your Stripe Dashboard
- `MAIL_USERNAME` and `MAIL_PASSWORD`: Set up an app-specific password in Gmail settings

Important notes:
- Never commit your `.env` file to version control
- Keep your `.env` file secure and never share it
- If you're using Gmail for email, you'll need to generate an app-specific password instead of using your regular Gmail password
- For production, ensure `SESSION_COOKIE_SECURE` is set to `True` and you have HTTPS configured

3. Run the application:
```bash
python app.py
```

4. Access the application at `http://localhost:5000`

## Project Structure

- `/templates` - HTML templates
- `/static` - Static files (CSS, JS, images)
- `app.py` - Main application file
- `requirements.txt` - Python dependencies
- `.env` - Environment variables
