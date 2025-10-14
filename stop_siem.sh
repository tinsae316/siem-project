#!/bin/bash

# SIEM Tool - Stop Script
# This script stops all SIEM components

echo "🛑 Stopping SIEM Tool..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Kill processes from PID file if it exists
if [ -f siem_pids.txt ]; then
    print_status "Stopping processes from PID file..."
    PIDS=$(cat siem_pids.txt)
    for pid in $PIDS; do
        if kill -0 $pid 2>/dev/null; then
            kill $pid
            print_status "Stopped process $pid"
        fi
    done
    rm siem_pids.txt
fi

# Kill any remaining processes by name
print_status "Stopping remaining SIEM processes..."

# Kill collector processes
pkill -f "collector.main" 2>/dev/null && print_status "Stopped collector processes" || true

# Kill dashboard processes
pkill -f "next dev" 2>/dev/null && print_status "Stopped dashboard processes" || true

# Kill detection processes
pkill -f "Hard_.*_Detection.py" 2>/dev/null && print_status "Stopped detection processes" || true

# Stop Docker containers if running
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    print_status "Stopping Docker containers..."
    docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true
fi

print_success "All SIEM services stopped!"
