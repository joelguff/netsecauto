"""
Ping monitoring utility for network devices
"""
import subprocess
import re
import time
import json
import threading
import queue
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class PingMonitor:
    """Class for monitoring devices via ping"""
    
    def __init__(self, count: int = 5, timeout: int = 2):
        """Initialize the ping monitor
        
        Args:
            count (int, optional): Number of ping packets to send. Defaults to 5.
            timeout (int, optional): Timeout in seconds. Defaults to 2.
        """
        self.count = count
        self.timeout = timeout
        self._running = False
        self._devices_queue = queue.Queue()
        self._results_queue = queue.Queue()
        self._monitor_thread = None
        
    def ping_device(self, ip_address: str) -> Dict:
        """Ping a device and return stats
        
        Args:
            ip_address (str): IP address to ping
            
        Returns:
            Dict: Dictionary with ping results including latency, packet_loss, and status
        """
        try:
            # Run ping command
            if self.count <= 0:
                self.count = 1
                
            # Using subprocess to run ping command
            cmd = ["ping", "-c", str(self.count), "-W", str(self.timeout), ip_address]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse ping output
            output = result.stdout
            
            # Check if ping was successful
            if result.returncode != 0:
                return {
                    "ip_address": ip_address,
                    "latency_ms": 0.0,
                    "packet_loss": 100.0,
                    "status": "down",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Extract statistics using regex
            latency_match = re.search(r"min/avg/max/(mdev|stddev) = ([0-9.]+)/([0-9.]+)/([0-9.]+)", output)
            packet_loss_match = re.search(r"([0-9.]+)% packet loss", output)
            
            latency = 0.0
            packet_loss = 100.0
            status = "down"
            
            if latency_match:
                latency = float(latency_match.group(3))  # Average latency
                
            if packet_loss_match:
                packet_loss = float(packet_loss_match.group(1))
                
            # Determine status based on packet loss
            if packet_loss == 0:
                status = "up"
            elif packet_loss < 50:
                status = "degraded"
            else:
                status = "down"
                
            return {
                "ip_address": ip_address,
                "latency_ms": latency,
                "packet_loss": packet_loss,
                "status": status,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            # Return error status on exception
            return {
                "ip_address": ip_address,
                "latency_ms": 0.0,
                "packet_loss": 100.0,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            
    def _monitor_worker(self):
        """Worker function for continuous monitoring"""
        while self._running:
            try:
                # Get device info from queue with timeout
                device_info = self._devices_queue.get(timeout=1)
                
                # Ping the device
                ping_result = self.ping_device(device_info["ip_address"])
                
                # Combine ping result with device info
                result = {**device_info, **ping_result}
                
                # Add result to results queue
                self._results_queue.put(result)
                
                # Sleep for a short interval to reduce CPU usage
                time.sleep(0.2)
                
            except queue.Empty:
                # Queue is empty, wait for new devices
                time.sleep(0.5)
            except Exception as e:
                # Log any other exceptions
                print(f"Error in ping monitor: {str(e)}")
                time.sleep(1)
                
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self._running:
            self._running = True
            self._monitor_thread = threading.Thread(target=self._monitor_worker)
            self._monitor_thread.daemon = True
            self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
            
    def add_device(self, device_id: int, name: str, ip_address: str):
        """Add a device to the monitoring queue
        
        Args:
            device_id (int): Device ID in the database
            name (str): Device name
            ip_address (str): Device IP address
        """
        self._devices_queue.put({
            "device_id": device_id,
            "name": name,
            "ip_address": ip_address
        })
        
    def get_result(self, timeout: int = 0) -> Optional[Dict]:
        """Get a ping result from the queue
        
        Args:
            timeout (int, optional): Timeout in seconds. Defaults to 0 (non-blocking).
            
        Returns:
            Optional[Dict]: Ping result or None if queue is empty
        """
        try:
            return self._results_queue.get(timeout=timeout)
        except queue.Empty:
            return None
            
    def get_all_results(self) -> List[Dict]:
        """Get all ping results from the queue
        
        Returns:
            List[Dict]: List of ping results
        """
        results = []
        while not self._results_queue.empty():
            results.append(self._results_queue.get_nowait())
        return results