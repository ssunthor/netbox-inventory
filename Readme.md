cd ~/halo-mvp/backend
python3 -m venv .venv
source .venv/bin/activate
uvicorn app.main:app --reload --port 15174

pip install -r requirements.txt