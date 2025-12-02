#!/bin/bash
echo "Stopping all python processes..."
sudo killall -9 python python3 2>/dev/null
sleep 3

echo "Checking ports..."
while sudo ss -tlnp | grep -qE ':(5050|80|443)'; do
    echo "Waiting for ports to clear..."
    sleep 1
done
echo "Ports clear."

echo "Starting bridge..."
cd /home/doug/yahoo-discord-bridge
source venv/bin/activate
python bridge_native.py &

sleep 3
echo "Bridge started. Check logs with: tail -f bridge.log"
