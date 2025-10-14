# SIEM Tool - Complete Setup Guide

This is a comprehensive Security Information and Event Management (SIEM) tool with four main components:

1. **Collector** - Collects logs via HTTP endpoint and file watching
2. **Database** - PostgreSQL database for storing logs and alerts  
3. **Detection** - Python scripts that analyze logs for security threats
4. **Dashboard** - Next.js web interface to view logs and alerts

## 🚀 Quick Start (Recommended)

### Prerequisites
- Docker and Docker Compose installed
- Python 3.11+ (for running detection scripts manually)

### Run Everything at Once
```bash
# Make the script executable (already done)
chmod +x run_all.sh

# Run all components
./run_all.sh
```

This will:
- Start PostgreSQL database
- Build and run the collector (FastAPI)
- Build and run the dashboard (Next.js)
- Start Filebeat for log collection
- Run detection scripts in the background
- Create sample test logs

### Access the Services
- **Dashboard**: http://localhost:3002
- **Collector API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Database**: localhost:5432

## 🔧 Manual Setup (Alternative)

### 1. Database Setup
```bash
# Start PostgreSQL with Docker
docker-compose up db -d

# Or use local PostgreSQL
# Make sure PostgreSQL is running on port 5432
# Database: siem, User: user, Password: password
```

### 2. Collector Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variable
export DATABASE_URL="postgresql://user:password@localhost:5432/siem"

# Run collector
python -m collector.main
```

### 3. Dashboard Setup
```bash
cd dashboard

# Install dependencies
npm install

# Set environment variables
echo 'DATABASE_URL="postgresql://user:password@localhost:5432/siem"' > .env
echo 'JWT_SECRET="your-strong-secret-key"' >> .env

# Generate Prisma client
npx prisma generate

# Run dashboard
npm run dev
```

### 4. Detection Scripts
```bash
cd detection

# Run brute force detection
python3 Hard_Bruteforce_Detection.py

# Run SQL injection detection  
python3 Hard_SQL_Injection.py

# Run XSS detection
python3 Hard_XSS_Detection.py

# Run endpoint scan detection
python3 Hard_Endpoint_Scan_Detection.py

# Run suspicious admin detection
python3 Hard_Suspicious_Admin.py
```

### 5. Log Collection (Filebeat)
```bash
# Update filebeat.yml with correct paths
# Then run Filebeat
./filebeat -e -c filebeat.yml
```

## 📊 Data Flow

```
Log Files → Filebeat → Collector API → Database
                                    ↓
Detection Scripts ← Database ← Dashboard (Web UI)
```

## 🔍 API Endpoints

### Collector API (Port 8000)
- `POST /collect` - Receive logs from Filebeat or other sources
- `GET /docs` - API documentation

### Dashboard API (Port 3002)
- `/` - Landing page
- `/login` - User authentication
- `/dashboard` - Main dashboard
- `/logs` - View collected logs
- `/alerts` - View security alerts

## 📝 Sample Log Formats

The collector accepts logs in multiple formats:

### Structured Logs
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": {"category": "authentication", "outcome": "failure"},
  "source": {"ip": "192.168.1.100"},
  "user": {"name": "admin"},
  "message": "Failed login attempt"
}
```

### Filebeat Logs
```json
{
  "message": "192.168.1.100 - - [15/Jan/2024:10:30:00] \"POST /login HTTP/1.1\" 401 1234"
}
```

## 🛡️ Detection Rules

The system includes detection for:
- **Brute Force Attacks** - Multiple failed login attempts
- **SQL Injection** - Suspicious SQL patterns in requests
- **XSS Attacks** - Cross-site scripting attempts
- **Endpoint Scanning** - Port scanning behavior
- **Suspicious Admin Activity** - Unusual admin actions

## 🔧 Configuration

### Environment Variables

**Collector (.env)**
```
DATABASE_URL=postgresql://user:password@localhost:5432/siem
```

**Dashboard (.env)**
```
DATABASE_URL=postgresql://user:password@localhost:5432/siem
JWT_SECRET=your-strong-secret-key
```

**Filebeat (filebeat.yml)**
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/your/logs/*.log

output.http:
  hosts: ["http://localhost:8000/collect"]
  content_type: application/json
```

## 📈 Monitoring

### View Logs
```bash
# Docker logs
docker-compose logs -f collector
docker-compose logs -f dashboard
docker-compose logs -f db

# Or view all
docker-compose logs -f
```

### Database Access
```bash
# Connect to PostgreSQL
docker-compose exec db psql -U user -d siem

# View logs table
SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10;

# View alerts table  
SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10;
```

## 🛑 Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clears database)
docker-compose down -v
```

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts**: Make sure ports 3002, 8000, and 5432 are available
2. **Database connection**: Check DATABASE_URL format
3. **Permission issues**: Ensure filebeat.yml paths are accessible
4. **Missing dependencies**: Run `pip install -r requirements.txt` and `npm install`

### Logs and Debugging
```bash
# Check service status
docker-compose ps

# View detailed logs
docker-compose logs collector
docker-compose logs dashboard
docker-compose logs db

# Restart a specific service
docker-compose restart collector
```

## 📚 Additional Resources

- **Collector Documentation**: See `collector/README.md`
- **Dashboard Documentation**: See `dashboard/README.md`
- **Detection Rules**: See individual files in `detection/` directory

## 🤝 Contributing

Each component can be developed independently:
- Collector: FastAPI application for log collection
- Dashboard: Next.js application for visualization
- Database: PostgreSQL schema and connections
- Detection: Python scripts for security analysis

## 📄 License

This project is part of a SIEM development exercise.
