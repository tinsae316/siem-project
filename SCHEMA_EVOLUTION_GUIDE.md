# Automatic Database Schema Evolution for SIEM

This guide explains how the automatic database schema evolution system works in your SIEM project and how to use it effectively.

## 🎯 Overview

The schema evolution system automatically detects new fields in incoming logs and adds corresponding columns to your Neon PostgreSQL database. This eliminates the need for manual database schema updates when new log sources or security tools are added.

## 🏗️ Architecture

### Core Components

1. **SchemaEvolution** (`collector/schema_evolution.py`)
   - Analyzes incoming logs for new fields
   - Infers appropriate PostgreSQL data types
   - Manages automatic column addition

2. **MigrationManager** (`collector/migration_manager.py`)
   - Tracks schema changes and migrations
   - Provides rollback capabilities
   - Maintains migration history

3. **Enhanced Database Layer** (`collector/enhanced_db.py`)
   - Integrates schema evolution with log insertion
   - Provides dynamic INSERT statements
   - Handles schema-aware data processing

## 🚀 How It Works

### 1. Log Analysis
When a new log arrives, the system:
- Extracts all field names and values
- Compares against existing database schema
- Identifies new fields not present in current columns

### 2. Type Inference
For each new field, the system determines the appropriate PostgreSQL type:
- `string` → `TEXT`
- `int` → `INTEGER`
- `float` → `NUMERIC`
- `bool` → `BOOLEAN`
- `array` → `TEXT[]` or `JSONB`
- `object` → `JSONB`
- IP addresses → `INET`
- Timestamps → `TIMESTAMPTZ`

### 3. Schema Evolution
- Generates `ALTER TABLE` statements for new columns
- Executes changes in a transaction
- Records migration for rollback capability
- Updates internal schema cache

### 4. Dynamic Insertion
- Builds INSERT statements based on current schema
- Handles both standard and new fields
- Maintains data integrity

## 📋 Usage Examples

### Basic Usage
The system works automatically when you use the enhanced database functions:

```python
from collector.enhanced_db import init_enhanced_db, insert_log_with_evolution

# Initialize with schema evolution
pool = await init_enhanced_db()

# Insert log (schema evolution happens automatically)
await insert_log_with_evolution(pool, log_data)
```

### Example: New Security Tool Integration

When you add a new security tool that generates logs with new fields:

```python
# Log from new security tool with new fields
security_log = {
    "timestamp": "2024-01-15T10:30:00Z",
    "source": {"ip": "192.168.1.100"},
    "event": {"outcome": "blocked"},
    "message": "Threat detected",
    # NEW FIELDS - will trigger schema evolution
    "threat_score": 8.5,
    "malware_family": "Trojan.Generic",
    "ioc_type": "IP",
    "confidence_level": "high"
}

# System automatically:
# 1. Detects new fields: threat_score, malware_family, ioc_type, confidence_level
# 2. Adds columns to database with appropriate types
# 3. Records migration for rollback
# 4. Inserts log with all fields
await insert_log_with_evolution(pool, security_log)
```

## 🛠️ Management Commands

### Schema Status
Check current schema status and migration history:

```bash
cd collector
python schema_manager.py status
```

Output:
```
🔍 SIEM Database Schema Status
==================================================
📊 Total Columns: 25
🔄 Migrations Applied: 3
📅 Latest Migration: auto_schema_evolution_20240115_103000
📝 Description: Automatic schema evolution: Added 4 new columns

📋 Current Columns (25):
   1. id
   2. timestamp
   3. source_ip
   4. source_port
   ...
   22. threat_score
   23. malware_family
   24. ioc_type
   25. confidence_level
```

### Test Schema Evolution
Test the system with sample data:

```bash
python schema_manager.py test
```

### Rollback Migrations
Rollback the latest migration:

```bash
python schema_manager.py rollback
```

Rollback a specific migration:

```bash
python schema_manager.py rollback --migration auto_schema_evolution_20240115_103000
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
cd collector
python test_schema_evolution.py
```

This test demonstrates:
- Standard log insertion (no schema changes)
- Security logs with new fields
- Network monitoring logs
- Application logs with new fields
- Schema evolution tracking
- Migration history

## 🔧 Configuration

### Environment Variables
Ensure your `.env` file contains:

```env
DATABASE_URL=postgresql://username:password@host:port/database
```

### Database Permissions
The system requires the following permissions:
- `CREATE TABLE` - for migration tracking
- `ALTER TABLE` - for adding columns
- `INSERT`, `SELECT` - for data operations

## 📊 Monitoring

### Schema Growth Tracking
Monitor schema evolution through:

1. **Migration History**: Track all schema changes
2. **Column Count**: Monitor total columns over time
3. **Field Detection**: See which new fields are being detected

### Performance Considerations
- Schema changes are atomic (all or nothing)
- New columns are added as nullable by default
- Existing data remains unaffected
- Large tables may experience brief locks during schema changes

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure database user has ALTER TABLE permissions
   - Check connection string and credentials

2. **Schema Evolution Fails**
   - Check database connectivity
   - Verify log data format
   - Review error logs for specific issues

3. **Rollback Issues**
   - Ensure migration history is intact
   - Check for conflicting schema changes
   - Verify rollback SQL is valid

### Debug Mode
Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🔄 Integration with Existing Code

### Updating Main Application
The system integrates seamlessly with your existing SIEM:

```python
# In collector/main.py
from collector.enhanced_db import init_enhanced_db, insert_log_with_evolution

# Replace init_db() with init_enhanced_db()
db_pool = await init_enhanced_db()

# Replace insert_log() with insert_log_with_evolution()
await insert_log_with_evolution(db_pool, log_dict)
```

### File Watcher Integration
Update your file watcher to use enhanced database:

```python
# In collector/file_watcher.py
from collector.enhanced_db import insert_log_with_evolution

# Use enhanced insertion in file processing
await insert_log_with_evolution(pool, parsed_log)
```

## 📈 Benefits

1. **Automatic Adaptation**: No manual schema updates needed
2. **Data Integrity**: All log data is captured, even with new fields
3. **Rollback Capability**: Safe schema changes with rollback options
4. **Scalability**: Handles diverse log sources automatically
5. **Maintenance**: Reduces database administration overhead

## 🔮 Future Enhancements

Potential improvements:
- Column type optimization based on data patterns
- Automatic indexing for frequently queried fields
- Schema versioning and compatibility checks
- Performance monitoring and optimization
- Integration with Prisma schema updates

## 📚 Additional Resources

- [PostgreSQL ALTER TABLE Documentation](https://www.postgresql.org/docs/current/sql-altertable.html)
- [Neon Database Documentation](https://neon.tech/docs)
- [Prisma Schema Management](https://www.prisma.io/docs/concepts/components/prisma-migrate)

---

**Note**: This system is designed to work with your existing Neon PostgreSQL database and maintains full compatibility with your current SIEM infrastructure.




