import os
from app import app, init_db, get_model_info

# Initialize database and ML model on worker startup
init_db()
try:
    get_model_info()
except Exception as e:
    print(f"[WSGI] ML Model preload notice: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
