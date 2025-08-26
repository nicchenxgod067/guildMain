# TCP BD BOT with Web Interface

A comprehensive TCP bot system for Free Fire with a modern web interface, featuring friend request management, account management, and real-time bot monitoring.

## 🚀 Features

- **TCP Bot System**: Real-time game server connection and monitoring
- **Web Interface**: Modern, responsive dashboard for bot management
- **Friend Request Management**: Send and remove friend requests using bot accounts
- **Account Management**: Add, remove, update bot accounts
- **Real-time Status**: Monitor bot online status and activity
- **Render Deployment Ready**: Optimized for cloud deployment with static token support

## 🔧 API Endpoints

### Core Endpoints
- `GET /` - Main web interface
- `GET /accounts` - List all bot accounts
- `GET /status_json` - Get bot status information

### Friend Management
- `GET /send_requests?bot_name={name}&uid={uid}` - Send friend request
- `GET /remove_friend?bot_name={name}&uid={uid}` - Remove friend
- `GET /available_bots` - List available bots for friend requests

### Account Management
- `GET /add_account?name={name}&uid={uid}&password={password}` - Add new account
- `GET /remove_account?name={name}` - Remove account
- `GET /update_account?name={name}&uid={uid}&password={password}` - Update account

## 🌐 Environment Variables

- `APP_SECRET` - Secret key for session management
- `DISCORD_WEBHOOK_URL` - Discord webhook for access requests
- `PORT` - Port for the application (set by Render)

## 🚀 Deployment

### Render Deployment
The application is optimized for Render deployment with the following features:

1. **Static Token Loading**: Automatically loads tokens from `token_bd.json` on startup
2. **Cloud-Optimized**: Works without requiring live bot login (which may be blocked in cloud environments)
3. **Gunicorn Support**: Uses production WSGI server for optimal performance

### Local Development
```bash
python app.py
```

### Production (Render)
```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

## 📁 Project Structure

```
├── app.py                 # Main Flask application
├── website/              # Web interface files
├── TCP+SPAM/            # Spam service and token management
│   └── spam friend/     # External spam service
│       └── token_bd.json # Static tokens for friend requests
├── render.yaml          # Render deployment configuration
├── Procfile            # Process configuration
└── requirements.txt     # Python dependencies
```

## 🔑 Token System

### Local Development
- Uses live tokens generated from bot login
- Requires successful game server connection

### Render Deployment
- Uses static tokens from `token_bd.json`
- No need for live bot login
- Ensures friend request endpoints work in cloud environment

## 🐛 Troubleshooting

### "No token found for bot" Error
This error occurs when:
1. **Local**: Bot hasn't logged in yet or login failed
2. **Render**: Static tokens not loaded properly

**Solution**: Check the `/available_bots` endpoint to see which bots are available.

### Render Deployment Issues
1. Ensure `token_bd.json` exists in the correct path
2. Check build logs for token loading messages
3. Verify the `/available_bots` endpoint returns bot names

## 📝 Recent Updates

- **Render Deployment Fix**: Added static token loading for cloud deployment
- **New Endpoint**: `/available_bots` for debugging available bots
- **Cloud Optimization**: Friend request endpoints work without live bot login

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License.
