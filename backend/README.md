
# System Monitor Backend

This is the Flask backend for the System Monitor Dashboard.

## Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the Flask application:
```bash
python app.py
```

The server will start on `http://localhost:5000`

## API Endpoints

- `/api/cpu-memory` - Get CPU and memory usage
- `/api/processes` - Get running processes
- `/api/network-connections` - Get network connections
- `/api/traffic-stats` - Get traffic anomaly data
- `/api/full-scan` - Run complete system scan
- `/api/save-scan` - Save current scan results
- `/api/health` - Health check endpoint

## CORS Setup

If you encounter CORS issues, add this to your app.py:

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Add this line after creating the Flask app
```
