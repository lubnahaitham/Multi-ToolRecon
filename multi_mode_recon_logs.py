#!/usr/bin/env python3
"""
    MultiRecon (Multi-Mode Recon Tool - Web & Network)
    ================================================
    
    This Python script demonstrates multi-threaded reconnaissance,
    separating "Web" scans from "Network" scans. Each category
    (Web/Network) has both "Standard" and "Aggressive" modes.
    
    Web Tools (examples):
      - theHarvester
      - Sublist3r
      - whois
      - dnsmap
      - wafw00f
      - Nmap
      - testssl.sh
      - Amass
      - dnsenum
      - dirsearch
      - Metagoofil
      - exiftool
    
    Network Tools (examples):
      - whois
      - dnsmap
      - unicornscan
      - Nmap
      - testssl.sh
      - traceroute (optional)
      - ping (optional)
      - etc.
    
    Author  : Lubna Haitham
    Date    : 2024-12-30
    
    DISCLAIMER:
    -----------
    - This script is for DEMONSTRATION PURPOSES ONLY.
    - Use responsibly and ONLY with proper authorization.
    - Multi-threading introduces concurrency considerations
      (e.g., tasks that rely on each other's output).
"""
import subprocess
import sys
import os
import threading
from queue import Queue
import socket
import pyfiglet

# For pretty table output
try:
    from tabulate import tabulate
except ImportError:
    print("[!] 'tabulate' library not installed. Please install with: pip install tabulate")
    sys.exit(1)

# For colored console output
try:
    from colorama import Fore, Style, init
    init()
except ImportError:
    class Fore:
        RED   = '\033[31m'
        GREEN = '\033[32m'
        YELLOW= '\033[33m'
        CYAN  = '\033[36m'
        RESET = '\033[0m'
    class Style:
        RESET_ALL = '\033[0m'


def banner():
    ascii_art = pyfiglet.figlet_format("MultiRecon", font="slant")
    print(f"{Fore.GREEN}{ascii_art}{Style.RESET_ALL}")
    print(rf"""{Fore.GREEN}
 ------------------------------------------------------------------
          MultiRecon                                            
 ------------------------------------------------------------------
 |   1) Web Standard Scan                                         |
 |   2) Web Aggressive Scan                                       |
 |   3) Network Standard Scan                                     |
 |   4) Network Aggressive Scan                                   |
 |   5) Exit                                                      |
 ------------------------------------------------------------------
       Developed by Lubna Haitham
 ==================================================================
 {Style.RESET_ALL}""")

def run_subprocess(command, desc, results_list, output_file=None):
    """
    Safely runs a command in a subprocess and prints status.
    Results are appended to results_list: [tool, status, description].
    If output_file is provided, stdout and stderr are written to the file.
    """
    tool_name = command[0]
    print(f"{Fore.YELLOW}[+] {desc}{Style.RESET_ALL}")

    try:
        if output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, check=True, stdout=f, stderr=subprocess.STDOUT)
        else:
            subprocess.run(command, check=True)
        results_list.append([tool_name, "Success", desc])
    except subprocess.CalledProcessError as e:
        error_message = f"Command failed: {' '.join(command)}\n    Error: {e}"
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
    Each task is a tuple: (command_list, description, output_file)
    """
    while True:
        try:
            command_info = task_queue.get_nowait()  # (command_list, description, output_file)
        except:
            break
        command, desc, output_file = command_info
        run_subprocess(command, desc, results_list, output_file)
        task_queue.task_done()


def run_parallel(tasks, results_list, num_threads=4):
    """
    Runs tasks in parallel using multiple threads.
    Each task is (command_list, description, output_file).
    """
    q = Queue()
    for t in tasks:
        q.put(t)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(q, results_list), daemon=True)
        t.start()
        threads.append(t)

    q.join()


def print_results_table(results_list):
    """
    Print results (tool, status, description) in a colored table.
    """
    table_data = []
    for tool, status, desc in results_list:
        if status == "Success":
            color_status = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        elif status in ("Failed", "Not Found"):
            color_status = f"{Fore.RED}{status}{Style.RESET_ALL}"
        else:
            color_status = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"

        table_data.append([tool, color_status, desc])

    print(tabulate(
        table_data,
        headers=[f"{Fore.CYAN}Tool{Style.RESET_ALL}",
                 f"{Fore.CYAN}Status{Style.RESET_ALL}",
                 f"{Fore.CYAN}Description{Style.RESET_ALL}"],
        tablefmt="fancy_grid"
    ))


def resolve_domain(domain):
    """
    Resolves a domain to its corresponding IP address.
    Returns the IP address as a string.
    """
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] Domain '{domain}' resolved to IP '{ip}'.{Style.RESET_ALL}")
        return ip
    except socket.gaierror:
        print(f"{Fore.RED}[!] Failed to resolve domain '{domain}'.{Style.RESET_ALL}")
        return None


def reverse_resolve_ip(ip):
    """
    Performs a reverse DNS lookup on an IP address to find its domain name.
    Returns the domain name as a string if found, else None.
    """
    try:
        domain = socket.gethostbyaddr(ip)[0]
        print(f"{Fore.GREEN}[+] IP '{ip}' reverse resolved to domain '{domain}'.{Style.RESET_ALL}")
        return domain
    except socket.herror:
        print(f"{Fore.YELLOW}[!] No domain found for IP '{ip}'.{Style.RESET_ALL}")
        return None


# --------------------------------------------------------------
# Web Scans
# --------------------------------------------------------------
def web_standard_scan(domain):
    """
    Perform a standard web reconnaissance scan (multi-threaded).
    Example set of tools for a standard web recon:
      - theHarvester
      - Sublist3r
      - whois
      - dnsmap
      - wafw00f
      - nmap (quick scan)
      - testssl.sh (fast check)
      - Metagoofil (limited)
      - exiftool (on Metagoofil output)
    """
    print(f"{Fore.MAGENTA}\n[+] Starting Web Standard Reconnaissance Scan on {domain}...\n{Style.RESET_ALL}")
    results_list = []

    # Resolve domain to IP
    resolved_ip = resolve_domain(domain)
    if not resolved_ip:
        print(f"{Fore.RED}[!] Cannot proceed without resolving the domain. Exiting scan.{Style.RESET_ALL}")
        return

    # Create Main Output Directory
    scan_type = "web_standard"
    main_output_dir = f"{domain}_{scan_type}"
    os.makedirs(main_output_dir, exist_ok=True)

    # Create Subdirectories for Each Tool
    tool_dirs = {
        "theHarvester": os.path.join(main_output_dir, "theHarvester"),
        "Sublist3r": os.path.join(main_output_dir, "Sublist3r"),
        "whois": os.path.join(main_output_dir, "whois"),
        "dnsmap": os.path.join(main_output_dir, "dnsmap"),
        "wafw00f": os.path.join(main_output_dir, "wafw00f"),
        "nmap": os.path.join(main_output_dir, "nmap"),
        "testssl.sh": os.path.join(main_output_dir, "testssl.sh"),
        "Metagoofil": os.path.join(main_output_dir, "Metagoofil"),
        "exiftool": os.path.join(main_output_dir, "exiftool"),
    }

    for dir_path in tool_dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    # Define Parallel Tasks
    parallel_tasks = [
        (
            ["theHarvester", "-d", domain, "-b", "all", "-l", "50"],
            "theHarvester (basic OSINT)",
            os.path.join(tool_dirs["theHarvester"], "theHarvester_output.txt")
        ),
        (
            ["sublist3r", "-d", domain, "-e", "ssl", "-o", os.path.join(tool_dirs["Sublist3r"], "subdomains.txt")],
            "Sublist3r (certificate transparency)",
            None  # Sublist3r already handles output
        ),
        (
            ["whois", domain],
            "whois lookup",
            os.path.join(tool_dirs["whois"], "whois_output.txt")
        ),
        (
            ["dnsmap", domain],
            "dnsmap (DNS brute force)",
            os.path.join(tool_dirs["dnsmap"], "dnsmap_output.txt")
        ),
        (
            ["wafw00f", domain],
            "wafw00f (WAF detection)",
            os.path.join(tool_dirs["wafw00f"], "wafw00f_output.txt")
        ),
        (
            ["nmap", "-F", resolved_ip],
            "nmap (quick scan: top 100 ports)",
            os.path.join(tool_dirs["nmap"], "nmap_output.txt")
        ),
        (
            ["testssl.sh", "--fast", domain],
            "testssl.sh (TLS info)",
            os.path.join(tool_dirs["testssl.sh"], "testssl_output.txt")
        ),
    ]

    run_parallel(parallel_tasks, results_list, num_threads=4)

    # Metagoofil + exiftool (sequential)
    # Metagoofil
    metagoofil_output_dir = tool_dirs["Metagoofil"]
    metagoofil_report = os.path.join(metagoofil_output_dir, "metagoofil_report.html")
    metagoofil_command = [
        "metagoofil",
        "-d", domain,
        "-t", "pdf",
        "-l", "10",
        "-n", "5",
        "-o", metagoofil_output_dir,
        "-f", metagoofil_report
    ]

    run_subprocess(metagoofil_command, "Metagoofil (limited PDF search)", results_list, os.path.join(tool_dirs["Metagoofil"], "metagoofil_output.txt"))

    # ExifTool
    if os.listdir(metagoofil_output_dir):
        metagoofil_files = [os.path.join(metagoofil_output_dir, f) for f in os.listdir(metagoofil_output_dir) if os.path.isfile(os.path.join(metagoofil_output_dir, f))]
        if metagoofil_files:
            exiftool_command = ["exiftool"] + metagoofil_files
            run_subprocess(exiftool_command, "exiftool on Metagoofil downloads", results_list, os.path.join(tool_dirs["exiftool"], "exiftool_output.txt"))
        else:
            print(f"{Fore.YELLOW}[!] No files found in '{metagoofil_output_dir}' for exiftool.{Style.RESET_ALL}")
            results_list.append(["exiftool", "Skipped", "No downloaded files"])
    else:
        print(f"{Fore.YELLOW}[!] No files found in '{metagoofil_output_dir}' for exiftool.{Style.RESET_ALL}")
        results_list.append(["exiftool", "Skipped", "No downloaded files"])

    print(f"{Fore.MAGENTA}\n[+] Web Standard Reconnaissance Scan Complete.\n{Style.RESET_ALL}")
    print_results_table(results_list)


def web_aggressive_scan(domain):
    """
    Perform an aggressive web reconnaissance scan (multi-threaded).
    Example set of tools for an aggressive web recon:
      - theHarvester
      - Sublist3r
      - Amass
      - dnsmap
      - dnsenum
      - whois
      - wafw00f
      - nmap (aggressive)
      - testssl.sh (full)
      - dirsearch
      - Metagoofil (broader)
      - exiftool (on Metagoofil output)
    """
    print(f"{Fore.MAGENTA}\n[+] Starting Web Aggressive Reconnaissance Scan on {domain}...\n{Style.RESET_ALL}")
    results_list = []

    # Resolve domain to IP
    resolved_ip = resolve_domain(domain)
    if not resolved_ip:
        print(f"{Fore.RED}[!] Cannot proceed without resolving the domain. Exiting scan.{Style.RESET_ALL}")
        return

    # Create Main Output Directory
    scan_type = "web_aggressive"
    main_output_dir = f"{domain}_{scan_type}"
    os.makedirs(main_output_dir, exist_ok=True)

    # Create Subdirectories for Each Tool
    tool_dirs = {
        "theHarvester": os.path.join(main_output_dir, "theHarvester"),
        "Sublist3r": os.path.join(main_output_dir, "Sublist3r"),
        "Amass": os.path.join(main_output_dir, "Amass"),
        "dnsmap": os.path.join(main_output_dir, "dnsmap"),
        "dnsenum": os.path.join(main_output_dir, "dnsenum"),
        "whois": os.path.join(main_output_dir, "whois"),
        "wafw00f": os.path.join(main_output_dir, "wafw00f"),
        "nmap": os.path.join(main_output_dir, "nmap"),
        "testssl.sh": os.path.join(main_output_dir, "testssl.sh"),
        "dirsearch": os.path.join(main_output_dir, "dirsearch"),
        "Metagoofil": os.path.join(main_output_dir, "Metagoofil"),
        "exiftool": os.path.join(main_output_dir, "exiftool"),
    }

    for dir_path in tool_dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    # Define Parallel Tasks
    parallel_tasks = [
        (
            ["theHarvester", "-d", domain, "-b", "all", "-l", "300"],
            "theHarvester (deeper OSINT)",
            os.path.join(tool_dirs["theHarvester"], "theHarvester_output.txt")
        ),
        (
            ["sublist3r", "-d", domain, "-e", "ssl", "-o", os.path.join(tool_dirs["Sublist3r"], "subdomains.txt")],
            "Sublist3r (certificate transparency)",
            None  # Sublist3r already handles output
        ),
        (
            ["amass", "enum", "-d", domain, "-o", os.path.join(tool_dirs["Amass"], "amass_output.txt")],
            "Amass (subdomain enumeration)",
            None  # Amass handles output via -o
        ),
        (
            ["dnsmap", domain],
            "dnsmap (DNS brute force)",
            os.path.join(tool_dirs["dnsmap"], "dnsmap_output.txt")
        ),
        (
            ["dnsenum", domain],
            "dnsenum (DNS enumeration)",
            os.path.join(tool_dirs["dnsenum"], "dnsenum_output.txt")
        ),
        (
            ["whois", domain],
            "whois lookup",
            os.path.join(tool_dirs["whois"], "whois_output.txt")
        ),
        (
            ["wafw00f", domain],
            "wafw00f (WAF detection)",
            os.path.join(tool_dirs["wafw00f"], "wafw00f_output.txt")
        ),
        (
            ["nmap", "-A", "-T4", resolved_ip],
            "nmap (aggressive scan)",
            os.path.join(tool_dirs["nmap"], "nmap_output.txt")
        ),
        (
            ["testssl.sh", domain],
            "testssl.sh (full TLS checks)",
            os.path.join(tool_dirs["testssl.sh"], "testssl_output.txt")
        ),
        (
            ["dirsearch", "-u", f"http://{domain}", "-e", "php,asp,txt,html", "-x", "403,404", "-o", os.path.join(tool_dirs["dirsearch"], "dirsearch_output.txt")],
            "dirsearch (brute-forcing directories)",
            None  # dirsearch handles output via -o
        ),
    ]

    run_parallel(parallel_tasks, results_list, num_threads=6)

    # Metagoofil + exiftool (sequential)
    # Metagoofil
    metagoofil_output_dir = tool_dirs["Metagoofil"]
    metagoofil_report = os.path.join(metagoofil_output_dir, "metagoofil_report.html")
    metagoofil_command = [
        "metagoofil",
        "-d", domain,
        "-t", "doc,ppt,pdf,xls",
        "-l", "100",
        "-n", "30",
        "-o", metagoofil_output_dir,
        "-f", metagoofil_report
    ]

    run_subprocess(metagoofil_command, "Metagoofil (doc,ppt,pdf,xls)", results_list, os.path.join(tool_dirs["Metagoofil"], "metagoofil_output.txt"))

    # ExifTool
    if os.listdir(metagoofil_output_dir):
        metagoofil_files = [os.path.join(metagoofil_output_dir, f) for f in os.listdir(metagoofil_output_dir) if os.path.isfile(os.path.join(metagoofil_output_dir, f))]
        if metagoofil_files:
            exiftool_command = ["exiftool"] + metagoofil_files
            run_subprocess(exiftool_command, "exiftool on Metagoofil downloads", results_list, os.path.join(tool_dirs["exiftool"], "exiftool_output.txt"))
        else:
            print(f"{Fore.YELLOW}[!] No files found in '{metagoofil_output_dir}' for exiftool.{Style.RESET_ALL}")
            results_list.append(["exiftool", "Skipped", "No downloaded files"])
    else:
        print(f"{Fore.YELLOW}[!] No files found in '{metagoofil_output_dir}' for exiftool.{Style.RESET_ALL}")
        results_list.append(["exiftool", "Skipped", "No downloaded files"])

    print(f"{Fore.MAGENTA}\n[+] Web Aggressive Reconnaissance Scan Complete.\n{Style.RESET_ALL}")
    print_results_table(results_list)


# --------------------------------------------------------------
# Network Scans
# --------------------------------------------------------------
def net_standard_scan(ip):
    """
    Perform a standard network reconnaissance scan (multi-threaded).
    Example set of tools for standard network recon:
      - whois
      - dnsmap
      - unicornscan
      - nmap (quick scan)
      - testssl.sh (fast check)
      - (Optional) traceroute, ping, etc.
    """
    print(f"{Fore.MAGENTA}\n[+] Starting Network Standard Reconnaissance Scan on {ip}...\n{Style.RESET_ALL}")
    results_list = []

    # Reverse resolve IP to domain
    resolved_domain = reverse_resolve_ip(ip)

    # Create Main Output Directory
    scan_type = "network_standard"
    main_output_dir = f"{ip}_{scan_type}"
    os.makedirs(main_output_dir, exist_ok=True)

    # Create Subdirectories for Each Tool
    tool_dirs = {
        "whois": os.path.join(main_output_dir, "whois"),
        "dnsmap": os.path.join(main_output_dir, "dnsmap"),
        "unicornscan": os.path.join(main_output_dir, "unicornscan"),
        "nmap": os.path.join(main_output_dir, "nmap"),
        "testssl.sh": os.path.join(main_output_dir, "testssl.sh"),
        # Uncomment if desired:
        # "traceroute": os.path.join(main_output_dir, "traceroute"),
        # "ping": os.path.join(main_output_dir, "ping"),
    }

    for dir_path in tool_dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    # Define Parallel Tasks
    parallel_tasks = [
        (
            ["whois", ip],
            "whois lookup",
            os.path.join(tool_dirs["whois"], "whois_output.txt")
        ),
        (
            ["dnsmap", ip],
            "dnsmap (DNS brute force / info)",
            os.path.join(tool_dirs["dnsmap"], "dnsmap_output.txt")
        ),
        (
            ["unicornscan", f"{ip}:a"],
            "unicornscan (all-port scan)",
            os.path.join(tool_dirs["unicornscan"], "unicornscan_output.txt")
        ),
        (
            ["nmap", "-F", ip],
            "nmap (quick scan: top 100 ports)",
            os.path.join(tool_dirs["nmap"], "nmap_output.txt")
        ),
        (
            ["testssl.sh", "--fast", ip],
            "testssl.sh (TLS info)",
            os.path.join(tool_dirs["testssl.sh"], "testssl_output.txt")
        ),
        # Uncomment if desired:
        # (
        #     ["traceroute", ip],
        #     "traceroute",
        #     os.path.join(tool_dirs["traceroute"], "traceroute_output.txt")
        # ),
        # (
        #     ["ping", "-c", "4", ip],
        #     "ping (4 packets)",
        #     os.path.join(tool_dirs["ping"], "ping_output.txt")
        # ),
    ]

    run_parallel(parallel_tasks, results_list, num_threads=4)

    print(f"{Fore.MAGENTA}\n[+] Network Standard Reconnaissance Scan Complete.\n{Style.RESET_ALL}")
    print_results_table(results_list)


def net_aggressive_scan(ip):
    """
    Perform an aggressive network reconnaissance scan (multi-threaded).
    Example set of tools for aggressive network recon:
      - whois
      - dnsmap
      - nmap (aggressive)
      - unicornscan (all ports)
      - testssl.sh (full)
      - (Optional) traceroute, ping, etc.
    """
    print(f"{Fore.MAGENTA}\n[+] Starting Network Aggressive Reconnaissance Scan on {ip}...\n{Style.RESET_ALL}")
    results_list = []

    # Reverse resolve IP to domain
    resolved_domain = reverse_resolve_ip(ip)

    # Create Main Output Directory
    scan_type = "network_aggressive"
    main_output_dir = f"{ip}_{scan_type}"
    os.makedirs(main_output_dir, exist_ok=True)

    # Create Subdirectories for Each Tool
    tool_dirs = {
        "whois": os.path.join(main_output_dir, "whois"),
        "dnsmap": os.path.join(main_output_dir, "dnsmap"),
        "nmap": os.path.join(main_output_dir, "nmap"),
        "unicornscan": os.path.join(main_output_dir, "unicornscan"),
        "testssl.sh": os.path.join(main_output_dir, "testssl.sh"),
        # Uncomment if desired:
        # "traceroute": os.path.join(main_output_dir, "traceroute"),
        # "ping": os.path.join(main_output_dir, "ping"),
    }

    for dir_path in tool_dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    # Define Parallel Tasks
    parallel_tasks = [
        (
            ["whois", ip],
            "whois lookup",
            os.path.join(tool_dirs["whois"], "whois_output.txt")
        ),
        (
            ["dnsmap", ip],
            "dnsmap (DNS brute force / info)",
            os.path.join(tool_dirs["dnsmap"], "dnsmap_output.txt")
        ),
        (
            ["nmap", "-A", "-T4", ip],
            "nmap (aggressive scan)",
            os.path.join(tool_dirs["nmap"], "nmap_output.txt")
        ),
        (
            ["unicornscan", f"{ip}:a"],
            "unicornscan (all-port scan)",
            os.path.join(tool_dirs["unicornscan"], "unicornscan_output.txt")
        ),
        (
            ["testssl.sh", ip],
            "testssl.sh (full TLS checks)",
            os.path.join(tool_dirs["testssl.sh"], "testssl_output.txt")
        ),
        # Uncomment if desired:
        # (
        #     ["traceroute", ip],
        #     "traceroute",
        #     os.path.join(tool_dirs["traceroute"], "traceroute_output.txt")
        # ),
        # (
        #     ["ping", "-c", "4", ip],
        #     "ping (4 packets)",
        #     os.path.join(tool_dirs["ping"], "ping_output.txt")
        # ),
    ]

    run_parallel(parallel_tasks, results_list, num_threads=6)

    print(f"{Fore.MAGENTA}\n[+] Network Aggressive Reconnaissance Scan Complete.\n{Style.RESET_ALL}")
    print_results_table(results_list)


# --------------------------------------------------------------
# Main
# --------------------------------------------------------------
def main():
    while True:
        banner()
        choice = input(f"{Fore.YELLOW}Enter your choice [1-5]: {Style.RESET_ALL}").strip()

        if choice == "1":
            # Web Standard
            domain = input(f"{Fore.CYAN}Enter domain for Web Standard Scan: {Style.RESET_ALL}").strip()
            if not domain:
                print(f"{Fore.RED}[!] Domain cannot be empty.{Style.RESET_ALL}")
                continue
            web_standard_scan(domain)

        elif choice == "2":
            # Web Aggressive
            domain = input(f"{Fore.CYAN}Enter domain for Web Aggressive Scan: {Style.RESET_ALL}").strip()
            if not domain:
                print(f"{Fore.RED}[!] Domain cannot be empty.{Style.RESET_ALL}")
                continue
            web_aggressive_scan(domain)

        elif choice == "3":
            # Network Standard
            ip = input(f"{Fore.CYAN}Enter IP for Network Standard Scan: {Style.RESET_ALL}").strip()
            if not ip:
                print(f"{Fore.RED}[!] IP address cannot be empty.{Style.RESET_ALL}")
                continue
            # Validate IP format
            try:
                socket.inet_aton(ip)
            except socket.error:
                print(f"{Fore.RED}[!] Invalid IP address format.{Style.RESET_ALL}")
                continue
            net_standard_scan(ip)

        elif choice == "4":
            # Network Aggressive
            ip = input(f"{Fore.CYAN}Enter IP for Network Aggressive Scan: {Style.RESET_ALL}").strip()
            if not ip:
                print(f"{Fore.RED}[!] IP address cannot be empty.{Style.RESET_ALL}")
                continue
            # Validate IP format
            try:
                socket.inet_aton(ip)
            except socket.error:
                print(f"{Fore.RED}[!] Invalid IP address format.{Style.RESET_ALL}")
                continue
            net_aggressive_scan(ip)

        elif choice == "5":
            # Exit
            print(f"{Fore.GREEN}[+] Exiting program.{Style.RESET_ALL}")
            sys.exit(0)

        else:
            print(f"{Fore.RED}[!] Invalid choice. Please select 1, 2, 3, 4, or 5.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
