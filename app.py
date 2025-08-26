import os
import sys
import importlib.util


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
    return module.app


# Resolve the path to the existing TCP BD BOT Flask app
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TCP_APP_PATH = os.path.join(ROOT_DIR, "TCP+SPAM", "TCP BD BOT", "app.py")

# Expose WSGI app for Gunicorn/Render
app = load_flask_app_from_path(TCP_APP_PATH)


if __name__ == "__main__":
    # Local dev run
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


