#!/bin/bash

# Kill any running node processes for these servers
echo "Stopping existing servers..."
pkill -f "node index.js" || true

# Start Auth Server in watch mode
echo "Starting Auth Server (Watch Mode)..."
cd auth-server
nohup npm run dev > auth_server.log 2>&1 &
AUTH_PID=$!
echo "Auth Server PID: $AUTH_PID"
cd ..

# Start MCP Server in watch mode
echo "Starting MCP Server (Watch Mode)..."
cd mcp-server
nohup npm run dev > mcp_server.log 2>&1 &
MCP_PID=$!
echo "MCP Server PID: $MCP_PID"
cd ..

echo "---------------------------------------------------"
echo "Servers are running in background with auto-restart."
echo "Logs are being written to:"
echo "  - auth-server/auth_server.log"
echo "  - mcp-server/mcp_server.log"
echo "---------------------------------------------------"
