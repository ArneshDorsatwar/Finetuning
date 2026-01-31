#!/bin/bash
# Comprehensive status monitoring for auto-generation

while true; do
    clear
    echo "========================================="
    echo "AUTO-GENERATION STATUS MONITOR"
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================="
    echo ""
    
    # Check running processes
    echo "📊 ACTIVE PROCESSES:"
    running=$(ps aux | grep "generate_synthetic_data.py" | grep -v grep)
    if [ -n "$running" ]; then
        echo "$running" | awk '{print "  ✓ " $11 " " $12 " " $13 " " $14 " " $15}'
        proc_count=$(echo "$running" | wc -l)
        echo "  Total: $proc_count processes running"
    else
        echo "  ⏸️  No generation processes running"
    fi
    echo ""
    
    # Check generated files
    echo "📁 GENERATED FILES:"
    if [ -d "data/synthetic" ]; then
        file_count=$(find data/synthetic -name "*_anthropic.json" -o -name "*_openai.json" 2>/dev/null | wc -l)
        echo "  Total topics: $file_count"
        
        total_size=$(du -sh data/synthetic 2>/dev/null | awk '{print $1}')
        echo "  Total size: $total_size"
        echo ""
        
        echo "  Latest 5 files:"
        ls -lht data/synthetic/*.json 2>/dev/null | head -5 | awk '{print "    " $9 " - " $5}'
    else
        echo "  No files generated yet"
    fi
    echo ""
    
    # Check master log
    echo "📋 LATEST LOG OUTPUT:"
    if [ -f "logs/auto_generation_master.log" ]; then
        tail -5 logs/auto_generation_master.log | sed 's/^/  /'
    else
        echo "  Master log not found"
    fi
    echo ""
    
    # Check for errors
    echo "⚠️  ERROR CHECK:"
    error_count=$(grep -i "error\|fail\|exception" logs/*.log 2>/dev/null | wc -l)
    if [ $error_count -gt 0 ]; then
        echo "  ⚠️  Found $error_count errors/warnings in logs"
        echo "  Recent errors:"
        grep -i "error\|fail" logs/*.log 2>/dev/null | tail -3 | sed 's/^/    /'
    else
        echo "  ✅ No errors detected"
    fi
    echo ""
    
    echo "========================================="
    echo "Next update in 60 seconds... (Ctrl+C to stop)"
    echo "========================================="
    
    sleep 60
done
