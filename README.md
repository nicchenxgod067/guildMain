# TCP Bot Application

A powerful TCP bot application with web interface for managing multiple bot accounts.

## Features

- **Multi-Account Bot Management**: Manage multiple bot accounts simultaneously
- **Web Interface**: Beautiful and responsive web dashboard
- **Real-time Monitoring**: Monitor bot status and performance
- **RESTful API**: Complete API for bot management
- **Auto-restart**: Automatic bot restart on failure
- **Secure Authentication**: Built-in security features

## API Endpoints

### Status
- `GET /api/status` - Get application status

### Accounts
- `GET /api/accounts` - Get all accounts
- `POST /api/accounts` - Add new account
- `DELETE /api/accounts/<name>` - Delete account

### Bot Management
- `POST /api/bots/start/<name>` - Start bot for account
- `POST /api/bots/stop/<name>` - Stop bot for account
- `GET /api/bots/status` - Get bot status

## Environment Variables

- `APP_SECRET` - Application secret key (auto-generated on Render)
- `DISCORD_WEBHOOK_URL` - Discord webhook for notifications
- `PORT` - Port number (auto-set by Render)

## Deployment

This application is configured for deployment on Render:

1. Connect your GitHub repository
2. Render will automatically detect the configuration
3. The app will be deployed with all necessary dependencies

## Local Development

1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python app.py`
3. Access the web interface at `http://localhost:5000`

## Project Structure

```
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── render.yaml           # Render deployment configuration
├── Procfile             # Process file for deployment
├── runtime.txt          # Python runtime specification
├── website/             # Web interface files
│   ├── index.html      # Main page
│   ├── script.js       # JavaScript functionality
│   └── styles.css      # Styling
├── *.py                # Bot and utility modules
└── *.json              # Configuration files
```

## License

This project is for educational purposes only.
