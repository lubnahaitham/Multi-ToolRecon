#!/usr/bin/env python3
"""
Multi-Mode Recon Tool (Web/Network, Standard/Aggressive)
========================================================
- Prompts user for domain (Web modes) or IP/subnet (Network modes).
- Runs tasks in parallel (multi-threaded).
- Organizes outputs into dedicated folders for each tool.
- Displays a final colored summary table for each mode.

Author : Lubna Haitham
Date   : 2024-12-30

DISCLAIMER:
-----------
- For DEMONSTRATION PURPOSES ONLY.
- Use responsibly and ONLY with proper authorization.
"""

import subprocess
import sys
import os
import threading
from queue import Queue
from datetime import datetime
import socket


# For pretty table output
try:
    from tabulate import tabulate
except ImportError:
    print("[!] 'tabulate' library not installed. Please install via: pip install tabulate")
    sys.exit(1)

# For colored console output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED    = '\033[31m'
        GREEN  = '\033[32m'
        YELLOW = '\033[33m'
        CYAN   = '\033[36m'
        RESET  = '\033[0m'
    class Style:
        RESET_ALL = '\033[0m'

# For dynamic ASCII art
try:
    import pyfiglet
except ImportError:
    print("[!] 'pyfiglet' library not installed. Please install via: pip install pyfiglet")
    sys.exit(1)

###############################################################################
# 1. Tools for Each Mode
###############################################################################

# Web Standard Tasks (Web-specific tools only)
WEB_STANDARD_TASKS = [
    {
        "tool_name": "theHarvester",
        "cmd": ["theHarvester", "-d", None, "-b", "all", "-l", "50"],
        "desc": "theHarvester (basic OSINT)"
    },
    {
        "tool_name": "sublist3r",
        "cmd": ["sublist3r", "-d", None, "-e", "ssl", "-o", "subdomains.txt"],
        "desc": "Sublist3r (crtsh subdomain enumeration)"
    },
    {
        "tool_name": "whois",
        "cmd": ["whois", None],
        "desc": "whois lookup"
    },
    {
        "tool_name": "dnsmap",
        "cmd": ["dnsmap", None],
        "desc": "dnsmap (DNS brute force)"
    },
    {
        "tool_name": "wafw00f",
        "cmd": ["wafw00f", None],
        "desc": "wafw00f (WAF detection)"
    },
    {
        "tool_name": "testssl.sh",
        "cmd": ["testssl.sh", "--fast", None],
        "desc": "testssl.sh (quick TLS info)"
    }
]

# Web Aggressive Tasks (Web-specific tools only)
WEB_AGGRESSIVE_TASKS = [
    {
        "tool_name": "theHarvester",
        "cmd": ["theHarvester", "-d", None, "-b", "all", "-l", "300"],
        "desc": "theHarvester (300 results)"
    },
    {
        "tool_name": "sublist3r",
        "cmd": ["sublist3r", "-d", None, "-e", "ssl", "-o", "subdomains.txt"],
        "desc": "Sublist3r (aggressive subdomain enumeration)"
    },
    {
        "tool_name": "amass",
        "cmd": ["amass", "enum", "-d", None, "-o", "amass_subdomains.txt"],
        "desc": "Amass (subdomain enumeration)"
    },
    {
        "tool_name": "dnsmap",
        "cmd": ["dnsmap", None],
        "desc": "dnsmap (DNS brute force, aggressive)"
    },
    {
        "tool_name": "dnsenum",
        "cmd": ["dnsenum", None],
        "desc": "dnsenum (DNS enumeration)"
    },
    {
        "tool_name": "whois",
        "cmd": ["whois", None],
        "desc": "whois lookup"
    },
    {
        "tool_name": "wafw00f",
        "cmd": ["wafw00f", None],
        "desc": "wafw00f (WAF detection)"
    },
    {
        "tool_name": "testssl.sh",
        "cmd": ["testssl.sh", None],
        "desc": "testssl.sh (full TLS checks)"
    },
    {
        "tool_name": "dirsearch",
        "cmd": ["dirsearch", "-u", None, "-e", "php,asp,txt,html", "-x", "403,404", "-o", "dirsearch_results.txt"],
        "desc": "dirsearch (hidden directories)"
    }
]

# Network Standard Tasks (Network-specific tools only)
NETWORK_STANDARD_TASKS = [
    {
        "tool_name": "theHarvester",
        "cmd": ["theHarvester", "-d", None, "-b", "all", "-l", "50"],
        "desc": "theHarvester (basic OSINT)"
    },
    {
        "tool_name": "dnsmap",
        "cmd": ["dnsmap", None],
        "desc": "dnsmap (DNS brute force)"
    },
    {
        "tool_name": "nmap",
        "cmd": ["nmap", "-F", None],
        "desc": "nmap (quick scan top 100 ports)"
    }
]

# Network Aggressive Tasks (Network-specific tools only)
NETWORK_AGGRESSIVE_TASKS = [
    {
        "tool_name": "theHarvester",
        "cmd": ["theHarvester", "-d", None, "-b", "all", "-l", "300"],
        "desc": "theHarvester (300 results)"
    },
    {
        "tool_name": "dnsmap",
        "cmd": ["dnsmap", None],
        "desc": "dnsmap (DNS brute force, aggressive)"
    },
    {
        "tool_name": "masscan",
        "cmd": ["masscan", None, "--top-ports", "1000", "--rate", "5000"],
        "desc": "masscan (top 1000 ports fast scan)"
    },
    {
        "tool_name": "unicornscan",
        "cmd": ["unicornscan", f"{None}:a"],
        "desc": "unicornscan (all-port scan)"
    },
    {
        "tool_name": "nmap",
        "cmd": ["nmap", "-A", "-T4", None],
        "desc": "nmap (aggressive scan)"
    },
    {
        "tool_name": "dnsenum",
        "cmd": ["dnsenum", None],
        "desc": "dnsenum (DNS enumeration)"
    }
]

###############################################################################
# 2. Utility Functions
###############################################################################

def banner():
    # Generate ASCII art for "MultiRecon" using pyfiglet
    ascii_art = pyfiglet.figlet_format("MultiRecon", font="slant")
    
    print(f"{Fore.GREEN}{ascii_art}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1) Web Standard Scan")
    print(f"{Fore.YELLOW}2) Web Aggressive Scan")
    print(f"{Fore.YELLOW}3) Network Standard Scan")
    print(f"{Fore.YELLOW}4) Network Aggressive Scan")
    print(f"{Fore.YELLOW}5) Exit")
    print(f"{Fore.GREEN}------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"      Developed by Lubna Haitham")
    print(f"{Fore.GREEN}===================================================================\n{Style.RESET_ALL}")

def check_tool_installed(tool_name):
    """
    Returns True if 'tool_name' is in PATH, else False.
    We'll skip it otherwise.
    """
    try:
        subprocess.run(["which", tool_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def build_task_list(task_defs, user_input, scan_dir):
    """
    Replaces None placeholders with user_input (domain or IP/subnet).
    Creates dedicated folders for each tool's output.
    Returns (tasks, missing_tools).
    Each task => (cmd_list, desc, tool_name, output_file).
    If the tool isn't installed, we skip it (noting it in missing_tools).
    """
    final_tasks = []
    missing_tools = []

    for item in task_defs:
        tname = item["tool_name"]
        if not check_tool_installed(tname):
            missing_tools.append(tname)
            continue

        cmd = item["cmd"][:]
        # Create tool-specific output directory
        tool_output_dir = os.path.join(scan_dir, tname)
        os.makedirs(tool_output_dir, exist_ok=True)

        output_file = None
        # Determine if tool has an output file option
        if "-o" in cmd:
            o_index = cmd.index("-o") + 1
            original_output = cmd[o_index]
            # Replace the output filename with the path inside the tool's directory
            new_output = os.path.join(tool_output_dir, original_output)
            cmd[o_index] = new_output
            output_file = new_output
        elif tname == "unicornscan":
            # For unicornscan, specify output to a file
            output_file = os.path.join(tool_output_dir, "unicornscan_output.txt")
            cmd += [f"--output-file={output_file}"]
        else:
            # For tools without '-o', redirect output to a file
            output_file = os.path.join(tool_output_dir, f"{tname}_output.txt")
            # We'll handle redirection in the subprocess call

        # Replace None placeholders with user_input
        for i, val in enumerate(cmd):
            if val is None:
                cmd[i] = user_input

        final_tasks.append((cmd, item["desc"], tname, output_file))

    return final_tasks, missing_tools

def run_subprocess(cmd, desc, tool_name, output_file, results_list):
    """
    Runs a command line, capturing outputs if output_file is specified.
    Records success or failure in results_list.
    """
    print(f"{Fore.YELLOW}[+] {desc}{Style.RESET_ALL}")
    try:
        if output_file and tool_name not in ["theHarvester", "sublist3r", "amass", "dirsearch"]:
            # For tools without built-in output options, redirect stdout and stderr
            with open(output_file, 'w') as f:
                subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.STDOUT)
        else:
            # For tools with built-in output options or those handling output internally
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results_list.append([tool_name, "Success", desc])
    except subprocess.CalledProcessError as e:
        error_message = f"Command failed: {' '.join(cmd)}\nError: {e}"
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"\n{error_message}\n")
        print(f"{Fore.RED}[!] {error_message}{Style.RESET_ALL}")
        results_list.append([tool_name, "Failed", desc])
    except FileNotFoundError:
        error_message = f"Tool not found: {tool_name}"
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"\n{error_message}\n")
        print(f"{Fore.RED}[!] {error_message}{Style.RESET_ALL}")
        results_list.append([tool_name, "Not Found", desc])

def worker(task_queue, results_list):
    """
    Worker thread function:
    Pulls tasks off the queue and runs them until queue is empty.
    Each task is a tuple: (cmd_list, desc, tool_name, output_file)
    """
    while True:
        try:
            cmd, desc, tname, output_file = task_queue.get_nowait()
        except:
            break
        run_subprocess(cmd, desc, tname, output_file, results_list)
        task_queue.task_done()

def run_in_parallel(tasks, results_list, num_threads=8):
    """
    Multi-threaded execution. Each task => (cmd, desc, tool_name, output_file).
    """
    q = Queue()
    for task in tasks:
        q.put(task)

    threads = []
    for _ in range(min(num_threads, len(tasks))):
        th = threading.Thread(target=worker, args=(q, results_list), daemon=True)
        th.start()
        threads.append(th)

    q.join()

def print_summary_table(results_list, missing_tools):
    """
    Prints a final colored summary table (Tool, Status, Description).
    Missing tools are highlighted in yellow.
    """
    table_data = []
    for tool, status, desc in results_list:
        if status == "Success":
            color_status = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        elif status == "Failed":
            color_status = f"{Fore.RED}{status}{Style.RESET_ALL}"
        else:
            color_status = status

        table_data.append([tool, color_status, desc])

    # Missing tools
    for mt in sorted(missing_tools):
        table_data.append([mt, f"{Fore.YELLOW}Not Installed{Style.RESET_ALL}", "Tool not found"])

    table_str = tabulate(
        table_data,
        headers=[f"{Fore.CYAN}Tool{Style.RESET_ALL}",
                 f"{Fore.CYAN}Status{Style.RESET_ALL}",
                 f"{Fore.CYAN}Description{Style.RESET_ALL}"],
        tablefmt="fancy_grid"
    )
    print(table_str)
    print()

###############################################################################
# 3. Mode-Specific
###############################################################################

def web_standard_mode():
    domain = input(f"{Fore.YELLOW}Enter domain (e.g. example.com): {Style.RESET_ALL}").strip()
    if not domain:
        print(f"{Fore.RED}[!] Domain cannot be empty.{Style.RESET_ALL}")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"{domain}_Web_Standard_{timestamp}"
    os.makedirs(scan_dir, exist_ok=True)
    print(f"{Fore.MAGENTA}[+] Web (Standard) scanning {domain}{Style.RESET_ALL}\n")
    results_list = []

    tasks, missing = build_task_list(WEB_STANDARD_TASKS, domain, scan_dir)
    run_in_parallel(tasks, results_list, num_threads=min(8, len(tasks)))

    print(f"{Fore.MAGENTA}[+] Web (Standard) Complete.{Style.RESET_ALL}\n")
    print_summary_table(results_list, missing)

def web_aggressive_mode():
    domain = input(f"{Fore.YELLOW}Enter domain (e.g. example.com): {Style.RESET_ALL}").strip()
    if not domain:
        print(f"{Fore.RED}[!] Domain cannot be empty.{Style.RESET_ALL}")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"{domain}_Web_Aggressive_{timestamp}"
    os.makedirs(scan_dir, exist_ok=True)
    print(f"{Fore.MAGENTA}[+] Web (Aggressive) scanning {domain}{Style.RESET_ALL}\n")
    results_list = []

    tasks, missing = build_task_list(WEB_AGGRESSIVE_TASKS, domain, scan_dir)
    run_in_parallel(tasks, results_list, num_threads=min(8, len(tasks)))

    print(f"{Fore.MAGENTA}[+] Web (Aggressive) Complete.{Style.RESET_ALL}\n")
    print_summary_table(results_list, missing)

def network_standard_mode():
    ip_subnet = input(f"{Fore.YELLOW}Enter IP or subnet (e.g. 192.168.1.0/24): {Style.RESET_ALL}").strip()
    if not ip_subnet:
        print(f"{Fore.RED}[!] IP address or subnet cannot be empty.{Style.RESET_ALL}")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Replace '/' with '_' to create a valid directory name
    safe_ip_subnet = ip_subnet.replace('/', '_')
    scan_dir = f"{safe_ip_subnet}_Network_Standard_{timestamp}"
    os.makedirs(scan_dir, exist_ok=True)
    print(f"{Fore.MAGENTA}[+] Network (Standard) scanning {ip_subnet}{Style.RESET_ALL}\n")
    results_list = []

    tasks, missing = build_task_list(NETWORK_STANDARD_TASKS, ip_subnet, scan_dir)
    run_in_parallel(tasks, results_list, num_threads=min(8, len(tasks)))

    print(f"{Fore.MAGENTA}[+] Network (Standard) Complete.{Style.RESET_ALL}\n")
    print_summary_table(results_list, missing)

def network_aggressive_mode():
    ip_subnet = input(f"{Fore.YELLOW}Enter IP or subnet (e.g. 192.168.1.0/24): {Style.RESET_ALL}").strip()
    if not ip_subnet:
        print(f"{Fore.RED}[!] IP address or subnet cannot be empty.{Style.RESET_ALL}")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Replace '/' with '_' to create a valid directory name
    safe_ip_subnet = ip_subnet.replace('/', '_')
    scan_dir = f"{safe_ip_subnet}_Network_Aggressive_{timestamp}"
    os.makedirs(scan_dir, exist_ok=True)
    print(f"{Fore.MAGENTA}[+] Network (Aggressive) scanning {ip_subnet}{Style.RESET_ALL}\n")
    results_list = []

    tasks, missing = build_task_list(NETWORK_AGGRESSIVE_TASKS, ip_subnet, scan_dir)
    run_in_parallel(tasks, results_list, num_threads=min(8, len(tasks)))

    print(f"{Fore.MAGENTA}[+] Network (Aggressive) Complete.{Style.RESET_ALL}\n")
    print_summary_table(results_list, missing)

###############################################################################
# 4. Main
###############################################################################

def main():
    while True:
        banner()
        choice = input(f"{Fore.YELLOW}Enter your choice [1=WebStd, 2=WebAgg, 3=NetStd, 4=NetAgg, 5=Exit]: {Style.RESET_ALL}").strip()

        if choice == "1":
            web_standard_mode()
        elif choice == "2":
            web_aggressive_mode()
        elif choice == "3":
            network_standard_mode()
        elif choice == "4":
            network_aggressive_mode()
        elif choice == "5":
            print(f"{Fore.GREEN}[+] Exiting program.{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please select 1-5.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
