#!/bin/bash
# Yahoo-Discord Bridge Server Control Script

SCRIPT_DIR="/home/doug/yahoo-discord-bridge"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"

stop_servers() {
    echo "Stopping bridge servers..."
    sudo pkill -9 -f "python.*bridge_native.py" 2>/dev/null
    sudo pkill -9 -f "python.*http_server.py" 2>/dev/null
    sleep 2

    # Force kill anything on our ports
    sudo fuser -k 5050/tcp 2>/dev/null
    sudo fuser -k 80/tcp 2>/dev/null
    sleep 1

    # Wait for ports to be free
    while sudo ss -tlnp | grep -qE ':(5050|80)\s'; do
        echo "Waiting for ports to clear..."
        sleep 1
    done
    echo "Servers stopped. Ports are free."
}

start_servers() {
    cd "$SCRIPT_DIR"

    echo "Starting YMSG bridge (port 5050)..."
    $VENV_PYTHON bridge_native.py >> bridge.log 2>&1 &
    sleep 3

    echo "Starting HTTP server (port 80)..."
    sudo $VENV_PYTHON http_server.py >> http.log 2>&1 &
    sleep 2

    # Verify both are running
    if sudo ss -tlnp | grep -q ':5050'; then
        echo "YMSG bridge running on port 5050"
    else
        echo "WARNING: YMSG bridge failed to start!"
    fi

    if sudo ss -tlnp | grep -q ':80\s'; then
        echo "HTTP server running on port 80"
    else
        echo "WARNING: HTTP server failed to start!"
    fi

    echo ""
    echo "Servers started. Check logs with:"
    echo "  tail -f $SCRIPT_DIR/bridge.log"
    echo "  tail -f $SCRIPT_DIR/http.log"
}

status() {
    echo "=== Server Status ==="
    if sudo ss -tlnp | grep -q ':5050'; then
        echo "YMSG Bridge (5050): RUNNING"
    else
        echo "YMSG Bridge (5050): STOPPED"
    fi

    if sudo ss -tlnp | grep -q ':80\s'; then
        echo "HTTP Server (80):   RUNNING"
    else
        echo "HTTP Server (80):   STOPPED"
    fi
    echo ""
    sudo ss -tlnp | grep -E ':(5050|80)\s' 2>/dev/null
}

case "$1" in
    start)
        start_servers
        ;;
    stop)
        stop_servers
        ;;
    restart)
        stop_servers
        start_servers
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        echo ""
        echo "Commands:"
        echo "  start   - Start both YMSG bridge and HTTP server"
        echo "  stop    - Stop all servers and free ports"
        echo "  restart - Stop then start all servers"
        echo "  status  - Show server status"
        exit 1
        ;;
esac
