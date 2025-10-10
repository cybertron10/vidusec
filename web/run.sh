#!/bin/bash

# ViduSec Web Application Run Script

echo "🚀 Starting ViduSec Web Application..."

# Check if binary exists
if [ ! -f "vidusec-web" ]; then
    echo "📦 Binary not found. Building first..."
    ./build.sh
fi

# Create data directory
mkdir -p data/scans

# Set environment variables
export PORT=${PORT:-8080}

echo "🌐 Starting server on port $PORT..."
echo "📁 Data directory: $(pwd)/data"
echo "🔗 Web interface: http://localhost:$PORT"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the application
./vidusec-web
