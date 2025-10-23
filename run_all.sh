#!/bin/bash

# SIEM Tool - Complete Setup and Run Script
# This script sets up and runs all SIEM components

set -e

echo "🚀 Starting SIEM Tool Setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose plugin is available
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose plugin is not installed. Please install Docker Compose plugin first."
    exit 1
fi

# Create test logs directory if it doesn't exist
mkdir -p test_logs

# Create a sample test log file
cat > test_logs/test.log << EOF
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "GET /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S')] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
EOF

print_status "Created sample test logs"

# Create .env file for dashboard if it doesn't exist
if [ ! -f dashboard/.env ]; then
    cat > dashboard/.env << EOF
DATABASE_URL="postgresql://user:password@localhost:5432/siem"
JWT_SECRET="your-strong-secret-key-change-in-production"
EOF
    print_status "Created dashboard/.env file"
fi

# Create .env file for collector if it doesn't exist
if [ ! -f collector/.env ]; then
    cat > collector/.env << EOF
DATABASE_URL="postgresql://user:password@localhost:5432/siem"
EOF
    print_status "Created collector/.env file"
fi

print_status "Building and starting all services..."

# Build and start all services
docker compose up --build -d

print_status "Waiting for services to be ready..."

# Wait for database to be ready
sleep 10

# Check if services are running
print_status "Checking service status..."

if docker compose ps | grep -q "Up"; then
    print_success "All services are running!"
    echo ""
    print_status "Service URLs:"
    echo "  📊 Dashboard: http://localhost:3002"
    echo "  🔍 Collector API: http://localhost:8000"
    echo "  🗄  Database: localhost:5432"
    echo ""
    print_status "API Endpoints:"
    echo "  📥 Collect logs: POST http://localhost:8000/collect"
    echo "  📋 API docs: http://localhost:8000/docs"
    echo ""
    
    print_status "Running detection scripts..."
    
    # Run detection scripts
    print_status "Running brute force detection..."
    cd detection
    python3 Hard_Bruteforce_Detection.py &
    cd ..
    
    print_status "Running SQL injection detection..."
    cd detection
    python3 Hard_SQL_Injection.py &
    cd ..
    
    print_status "Running XSS detection..."
    cd detection
    python3 Hard_XSS_Detection.py &
    cd ..

    print_status "Running Port Scanning Detection..."
    cd detection
    python3 Port_Scanning_Detection.py &
    cd ..
    
    print_status "Running Suspicious File Activity..."
    cd detection
    python3 Suspicious_File_Activity.py &
    cd ..
    
    print_status "Running Suspicious Protocol Misuse detection..."
    cd detection
    python3 Suspicious_Protocol_Misuse.py &
    cd ..

    print_status "Running Hard_Suspicious_Admin detection..."
    cd detection
    python3 Hard_Suspicious_Admin.py &
    cd ..
    
    print_status "Running Hard_Endpoint_Scan_Detection detection..."
    cd detection
    python3 Hard_Endpoint_Scan_Detection.py &
    cd ..
    
    print_status "Running Firewall_Denied_Access detection..."
    cd detection
    python3 Firewall_Denied_Access.py &
    cd ..

    print_status "Running Firewall_Allowed_Suddenly_Blocked detection..."
    cd detection
    python3 Firewall_Allowed_Suddenly_Blocked.py &
    cd ..

    print_status "Running DoS_DDoS_Detection detection..."
    cd detection
    python3 DoS_DDoS_Detection.py &
    cd ..
    
    print_success "All detection scripts started!"
    
    echo ""
    print_status "🎉 SIEM Tool is now running!"
    print_status "📝 Check the dashboard at http://localhost:3002 to view logs and alerts"
    print_status "📊 Monitor logs with: docker compose logs -f"
    print_status "🛑 Stop all services with: docker compose down"
    
else
    print_error "Some services failed to start. Check logs with: docker compose logs"
    exit 1
fi