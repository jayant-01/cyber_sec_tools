import subprocess
import platform
import logging
from typing import Dict, List

class NetworkMapper:
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def ping_host(self) -> Dict:
        """Performs a ping to the target host."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', self.target]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            return {
                'status': 'success',
                'output': result.stdout
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ping failed for {self.target}: {e.stderr}")
            return {'status': 'error', 'output': e.stderr}
        except subprocess.TimeoutExpired:
            self.logger.error(f"Ping timed out for {self.target}")
            return {'status': 'error', 'output': 'Request timed out'}
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during ping: {e}")
            return {'status': 'error', 'output': str(e)}

    def traceroute_host(self) -> Dict:
        """Performs a traceroute to the target host."""
        command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', self.target]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
            return {
                'status': 'success',
                'output': result.stdout
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Traceroute failed for {self.target}: {e.stderr}")
            return {'status': 'error', 'output': e.stderr}
        except subprocess.TimeoutExpired:
            self.logger.error(f"Traceroute timed out for {self.target}")
            return {'status': 'error', 'output': 'Request timed out'}
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during traceroute: {e}")
            return {'status': 'error', 'output': str(e)}

    def run_all_scans(self) -> Dict:
        """Runs all network mapping scans."""
        results = {
            'target': self.target,
            'ping_results': self.ping_host(),
            'traceroute_results': self.traceroute_host()
        }
        return results

    def generate_report(self, scan_results: Dict) -> str:
        """Generates a human-readable report of the network mapping results."""
        report = f"Network Mapping Report for {scan_results['target']}\n"
        report += "=" * 50 + "\n\n"

        report += "Ping Results:\n"
        report += "-" * 20 + "\n"
        ping_data = scan_results.get('ping_results', {})
        if ping_data['status'] == 'success':
            report += ping_data['output'] + "\n"
        else:
            report += f"Error: {ping_data['output']}\n"
        report += "\n"

        report += "Traceroute Results:\n"
        report += "-" * 20 + "\n"
        traceroute_data = scan_results.get('traceroute_results', {})
        if traceroute_data['status'] == 'success':
            report += traceroute_data['output'] + "\n"
        else:
            report += f"Error: {traceroute_data['output']}\n"
        report += "\n"

        return report 