import os
import sys
import importlib.util
import asyncio
from threading import Thread


def load_flask_app_from_path(module_path):
    module_path = os.path.abspath(module_path)
    spec = importlib.util.spec_from_file_location("tcp_bd_bot_app", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "app"):
        raise AttributeError("Loaded module does not export 'app'")
    return module.app, module


# Resolve the path to the existing TCP BD BOT Flask app
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TCP_APP_PATH = os.path.join(ROOT_DIR, "TCP+SPAM", "TCP BD BOT", "app.py")

# Load both the Flask app and the module for TCP bot functionality
app, tcp_module = load_flask_app_from_path(TCP_APP_PATH)


def start_tcp_bot():
    """Start the TCP bot functionality in a separate thread"""
    try:
        print("Starting TCP bot functionality...")
        # Start the TCP bot's main async function
        asyncio.run(tcp_module.main_async())
    except Exception as e:
        print(f"Error starting TCP bot: {e}")


if __name__ == "__main__":
    # Start TCP bot in a separate thread
    tcp_thread = Thread(target=start_tcp_bot)
    tcp_thread.daemon = True
    tcp_thread.start()
    
    # Start Flask app
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
else:
    # For production (Render), start TCP bot when module is imported
    tcp_thread = Thread(target=start_tcp_bot)
    tcp_thread.daemon = True
    tcp_thread.start()


