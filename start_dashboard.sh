#!/bin/bash

# Kill ports 8000 and 3000 just in case
fuser -k 8000/tcp 2>/dev/null
fuser -k 3000/tcp 2>/dev/null

# Activate venv if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Warning: No virtual environment found. Using system python."
    export PATH=$PATH:$HOME/.local/bin
fi

echo "Starting Backend..."
export PYTHONPATH=$PYTHONPATH:$(pwd)
python3 -m uvicorn src.dashboard.backend.main:app --reload --port 8000 &
BACKEND_PID=$!

echo "Starting Frontend..."
cd src/dashboard/frontend
npm run dev &
FRONTEND_PID=$!

echo "Command Center is live!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT

wait
