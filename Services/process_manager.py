import subprocess
import psutil
import os
import threading
import logging
import signal

logger = logging.getLogger(__name__)

class ProcessManager:
    """
    Global manager to track and safely terminate all security tool subprocesses.
    Prevents orphaned processes (ZAP, SQLMap, Nmap) from lingering if Flask crashes.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ProcessManager, cls).__new__(cls)
                cls._instance._processes = {} # { "user_id": { "tool": Popen, ... } }
                cls._instance._global_lock = threading.Lock()
        return cls._instance

    def register(self, user_id, tool_name, process):
        """Track a new Popen object for a specific user and tool."""
        user_id = str(user_id)
        with self._global_lock:
            if user_id not in self._processes:
                self._processes[user_id] = {}
            self._processes[user_id][tool_name] = process
            logger.debug(f"[ProcessManager] Registered {tool_name} (PID: {process.pid}) for user {user_id}")

    def unregister(self, user_id, tool_name):
        """Remove a process from tracking after it finishes naturally."""
        user_id = str(user_id)
        with self._global_lock:
            if user_id in self._processes and tool_name in self._processes[user_id]:
                del self._processes[user_id][tool_name]
                if not self._processes[user_id]:
                    del self._processes[user_id]

    def stop_user_tool(self, user_id, tool_name):
        """Terminate a specific tool for a specific user."""
        user_id = str(user_id)
        with self._global_lock:
            if user_id in self._processes and tool_name in self._processes[user_id]:
                process = self._processes[user_id][tool_name]
                self._terminate_process_tree(process)
                del self._processes[user_id][tool_name]
                return True
        return False

    def stop_all_for_user(self, user_id):
        """Terminate all active tools for a specific user."""
        user_id = str(user_id)
        with self._global_lock:
            if user_id in self._processes:
                for tool, process in list(self._processes[user_id].items()):
                    self._terminate_process_tree(process)
                del self._processes[user_id]
                return True
        return False

    def cleanup_all(self):
        """System-wide cleanup of all tracked processes. Call on shutdown."""
        with self._global_lock:
            count = 0
            for user_id, tools in self._processes.items():
                for tool, process in tools.items():
                    self._terminate_process_tree(process)
                    count += 1
            self._processes.clear()
            if count > 0:
                logger.info(f"[ProcessManager] Cleaned up {count} orphaned processes.")

    def _terminate_process_tree(self, process):
        """Recursively kills a process and all its children."""
        try:
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)
            for child in children:
                child.terminate()
            parent.terminate()
            
            # Wait briefly for natural termination
            gone, alive = psutil.wait_procs(children + [parent], timeout=3)
            for survivor in alive:
                survivor.kill() # Force kill if still alive
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.error(f"[ProcessManager] Error terminating process {process.pid}: {e}")

# Singleton instance
process_manager = ProcessManager()
