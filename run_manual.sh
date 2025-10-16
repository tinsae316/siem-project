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

# ---- Robust project path resolution ----
# Directory where this script resides (project root assumed)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

print_status "Detected project root: $PROJECT_ROOT"

# Helper function to safely source env files
safe_source_env() {
    local env_path="$1"
    if [ -f "$env_path" ]; then
        set -a
        # shellcheck disable=SC1090
        source "$env_path"
        set +a
        print_status "Environment variables loaded from $env_path"
    else
        print_warning "$env_path not found"
    fi
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

# Install Node.js dependencies (inside dashboard/)
print_status "Installing Node.js dependencies..."
if [ -f dashboard/package.json ]; then
    pushd dashboard > /dev/null
    # prefer npm ci if package-lock.json exists, otherwise npm install
    if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
        npm ci
    else
        npm install
    fi
    popd > /dev/null
else
    print_error "dashboard/package.json not found. Please ensure the dashboard directory contains a package.json"
    echo "You can create one with: (cd dashboard && npm init -y)"
    exit 1
fi

# Generate Prisma client
print_status "Generating Prisma client..."
pushd dashboard > /dev/null
npx prisma generate --schema=prisma/schema.prisma
popd > /dev/null


print_success "All dependencies installed!"

print_status "Starting services..."

# Ensure Python can import local packages (collector, etc.)
export PYTHONPATH="$PROJECT_ROOT"
print_status "PYTHONPATH set to $PYTHONPATH"

# Start collector in background
print_status "Starting collector (FastAPI) on port 8000..."
safe_source_env "$PROJECT_ROOT/.env"           # root .env for collector
# Run collector as module so package imports like `from collector import ...` work
python3 -m collector.main &
COLLECTOR_PID=$!

# Wait a moment for collector to start
sleep 5

# Start dashboard in background
print_status "Starting dashboard (Next.js) on port 3002..."
pushd "$PROJECT_ROOT/dashboard" > /dev/null
safe_source_env "$PROJECT_ROOT/dashboard/.env" # dashboard specific env
npm run dev &
DASHBOARD_PID=$!
popd > /dev/null

# Wait a moment for dashboard to start
sleep 10

# Start detection scripts in background (only if detection folder exists)
print_status "Starting detection scripts..."
if [ -d "$PROJECT_ROOT/detection" ]; then
    pushd "$PROJECT_ROOT/detection" > /dev/null
    export PYTHONPATH="$PROJECT_ROOT"   # ensure detection scripts can import local packages
    # Start brute force detection
    python3 Hard_Bruteforce_Detection.py &
    DETECTION_PID1=$!

    # Start SQL injection detection
    python3 Hard_SQL_Injection.py &
    DETECTION_PID2=$!

    # Start XSS detection
    python3 Hard_XSS_Detection.py &
    DETECTION_PID3=$!

    python3 Port_Scanning_Detection.py &
    DETECTION_PID4=$!

    python3 Suspicious_File_Activity.py &
    DETECTION_PID5=$!

    python3 Suspicious_Protocol_Misuse.py &
    DETECTION_PID6=$!

    python3 Hard_Suspicious_Admin.py &
    DETECTION_PID7=$!

    python3 Hard_Endpoint_Scan_Detection.py &
    DETECTION_PID8=$!

    python3 Firewall_Denied_Access.py &
    DETECTION_PID9=$!

    python3 Firewall_Allowed_Suddenly_Blocked.py &
    DETECTION_PID10=$!

    python3 DoS_DDoS_Detection.py &
    DETECTION_PID11=$!

    popd > /dev/null
else
    print_warning "Detection directory not found at $PROJECT_ROOT/detection — skipping detection scripts"
    DETECTION_PID1=DETECTION_PID2=DETECTION_PID3=0
fi


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
