#!/bin/bash

# Monitoring Stack Management Script

echo "🚀 Managing Monitoring Stack..."

# Stop any existing containers
echo "📦 Stopping existing monitoring containers..."
docker-compose -f docker-compose.monitoring.yml down 2>/dev/null || true

# Remove any containers using our ports
echo "🧹 Cleaning up port conflicts..."
docker ps -a | grep -E "(auth-prometheus|auth-grafana|auth-alertmanager|auth-node-exporter)" | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true

# Start the monitoring stack
echo "🎯 Starting monitoring stack..."
docker-compose -f docker-compose.monitoring.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check status
echo ""
echo "📊 Service Status:"
docker-compose -f docker-compose.monitoring.yml ps

echo ""
echo "✅ Monitoring Stack Ready!"
echo ""
echo "🌐 Access URLs:"
echo "   Grafana:      http://localhost:3001 (admin/admin123)"
echo "   Prometheus:   http://localhost:9091"
echo "   AlertManager: http://localhost:9093"
echo ""
echo "📈 Your app metrics: http://localhost:3000/metrics"
echo ""
