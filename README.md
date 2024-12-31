# Multi-Mode Recon Tool

A **multi-threaded** reconnaissance framework for both **Web** and **Network** targets, featuring **two modes** of operation:

1. **Module 1 (Silent Mode)**
   - **Discards** logs during execution.
   - Displays only a **final color-coded summary table**: *Success*, *Failed*, *Not Installed*.

2. **Module 2 (Logs Mode)**
   - Prints **line-by-line output** from each tool in real time.
   - Optionally shows a **summary** table at the end or simply exits when done.

## Features

- **Web (Standard / Aggressive)**  
  - Prompts for a **domain** (e.g. `example.com`).

- **Network (Standard / Aggressive)**  
  - Prompts for an **IP** or **subnet** (e.g. `192.168.1.0/24`).

- **Multi-threaded** tasks for **faster** scanning (default 4–8 threads).  

- **Colorized** final table summarizing tool results:  
  - **Green**: Success  
  - **Red**: Failed  
  - **Yellow**: Not Installed  

## Installation

1. **Clone** this repo:
   ```bash
   git clone https://github.com/lubnahaitham/MultiRecon-Tool.git
   cd MultiRecon-Tool
   ```

2. Run the install.sh script to install dependencies automatically:

```bash
./install.sh
```
This script references apt_requirements.txt and install_commands.txt for system packages and additional tools.

## Usage

**Module 1 (Silent):**
Run python multi_mode_recon_silent.py (example name).
Menu appears, prompting for Web or Network, then Standard or Aggressive.
Enter domain (Web) or IP/subnet (Network).
Wait for the scan to complete.
A final summary table appears at the end.


**Module 2 (Logs):**
Run python multi_mode_recon_logs.py.
Similar menu flow: select mode (Web/Network, Standard/Aggressive).
Enter domain (Web) or IP/subnet (Network).
See real-time logs line-by-line, with MultiRecon-Tool prefixes.
Optionally a summary table or direct exit upon completion.

## Files
- **install.sh:** Automated installer for Python packages and system tools.
- **apt_requirements.txt:** Lists packages for apt-get install.
- **install_commands.txt:** Additional commands or references for installing required tools.
- **multi_mode_recon_silent.py (example):** Discards logs, final summary only.
- **multi_mode_recon_logs.py (example):** Real-time logs, optional summary.

## License
Open-source under the MIT License.
Use responsibly on targets you have explicit permission to test.

