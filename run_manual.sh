#!/bin/bash

# SIEM Tool - Manual Setup Script (Without Docker)
# This script sets up and runs all SIEM components manually

set -e

echo "🚀 Starting SIEM Tool Manual Setup..."

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

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    print_error "PostgreSQL is not installed. Please install PostgreSQL first:"
    echo "sudo apt update && sudo apt install postgresql postgresql-contrib"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js first:"
    echo "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -"
    echo "sudo apt-get install -y nodejs"
    exit 1
fi

print_status "All prerequisites are installed!"

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

# Setup PostgreSQL
print_status "Setting up PostgreSQL database..."

# Start PostgreSQL service
sudo systemctl start postgresql

# Create database and user (no password)
sudo -u postgres psql -c "CREATE DATABASE siem;" 2>/dev/null || print_warning "Database 'siem' already exists"
sudo -u postgres psql -c "CREATE USER user;" 2>/dev/null || print_warning "User 'user' already exists"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE siem TO user;" 2>/dev/null || print_warning "Privileges already granted"
sudo -u postgres psql -c "ALTER USER user CREATEDB;" 2>/dev/null || print_warning "User already has CREATEDB privilege"

print_success "PostgreSQL database setup complete"

# Install Python dependencies
print_status "Installing Python dependencies..."
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    print_warning "requirements.txt not found, installing basic dependencies..."
    pip install fastapi uvicorn asyncpg psycopg[binary,pool] watchdog pydantic python-dotenv geoip2
fi

# Install Node.js dependencies
print_status "Installing Node.js dependencies..."
cd dashboard
if [ -f package.json ]; then
    npm install
elsedatetime.datetime.utcnow()
    print_error "package.json not found in dashboard directory"
    exit 1
fi

# Generate Prisma client
print_status "Generating Prisma client..."
npx prisma generate

cd ..

print_success "All dependencies installed!"

print_status "Starting services..."

# Start collector in background
print_status "Starting collector (FastAPI) on port 8000..."
set -a; source .env; set +a
python3 -m collector.main &
COLLECTOR_PID=$!

# Wait a moment for collector to start
sleep 5

# Start dashboard in background
print_status "Starting dashboard (Next.js) on port 3002..."
cd dashboard
set -a; source ../.env; set +a
npm run dev &
DASHBOARD_PID=$!
cd ..

# Wait a moment for dashboard to start
sleep 10

# Start detection scripts in background
print_status "Starting detection scripts..."
export PYTHONPATH=$(pwd)
cd detection

# Start brute force detection
python3 Hard_Bruteforce_Detection.py &
DETECTION_PID1=$!

# Start SQL injection detection
python3 Hard_SQL_Injection.py &
DETECTION_PID2=$!

# Start XSS detection
python3 Hard_XSS_Detection.py &
DETECTION_PID3=$!

cd ..

print_success "All services are running!"
echo ""
print_status "Service URLs:"
echo "  📊 Dashboard: http://localhost:3002"
echo "  🔍 Collector API: http://localhost:8000"
echo "  📚 API Docs: http://localhost:8000/docs"
echo "  🗄️  Database: localhost:5432"
echo ""
print_status "Process IDs:"
echo "  Collector PID: $COLLECTOR_PID"
echo "  Dashboard PID: $DASHBOARD_PID"
echo "  Detection PIDs: $DETECTION_PID1, $DETECTION_PID2, $DETECTION_PID3"
echo ""
print_status "🎉 SIEM Tool is now running!"
print_status "📝 Check the dashboard at http://localhost:3002 to view logs and alerts"
echo ""
print_status "To stop all services, run:"
echo "  kill $COLLECTOR_PID $DASHBOARD_PID $DETECTION_PID1 $DETECTION_PID2 $DETECTION_PID3"

# Save PIDs to file for easy cleanup
echo "$COLLECTOR_PID $DASHBOARD_PID $DETECTION_PID1 $DETECTION_PID2 $DETECTION_PID3" > siem_pids.txt
print_status "Process IDs saved to siem_pids.txt"

# Keep script running
print_status "Press Ctrl+C to stop all services..."
wait
