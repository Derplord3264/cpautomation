#!/bin/bash

# Function to check for installed packages and suggest removal of unnecessary ones
check_installed_packages() {
    echo "Checking installed packages..."
    dpkg --get-selections | grep -v deinstall
}

# Function to score system security
score_security() {
    score=100

    # Check for unnecessary packages
    local unnecessary_packages=$(check_installed_packages | wc -l)
    if [[ $unnecessary_packages -gt 3 ]]; then
        echo "Critical: There are $unnecessary_packages unnecessary packages installed."
        score=$((score - 30))  # Heavy penalty for unnecessary packages
    fi

    # Check for root logon access
    if grep -q 'tty1' /etc/securetty; then
        echo "Critical: Root logon access is enabled."
        score=$((score - 20))  # Heavy penalty for root logon access
    fi

    # Check for active user accounts
    if [[ $(awk -F: '($3 == "0"){print}' /etc/passwd | wc -l) -gt 1 ]]; then
        echo "Critical: More than one user with UID 0 detected."
        score=$((score - 20))  # Heavy penalty for multiple root accounts
    fi

    # Check for firewall status
    if ! ufw status | grep -q "active"; then
        echo "Critical: Firewall is not active."
        score=$((score - 15))  # Significant penalty for inactive firewall
    fi

    # Check for ssh root login
    if grep -q 'PermitRootLogin yes' /etc/ssh/sshd_config; then
        echo "Critical: SSH root login is enabled."
        score=$((score - 15))  # Significant penalty for SSH root access
    fi

    # Check for outdated packages
    if [[ $(apt-get -u upgrade | grep -P '^\s*Inst' | wc -l) -gt 0 ]]; then
        echo "Critical: There are outdated packages."
        score=$((score - 10))  # Penalty for outdated packages
    fi

    echo "Security Score: $score/100"
}

# Function to fix common issues aggressively
fix_issues() {
    echo "Aggressively fixing common issues..."

    # Update and upgrade all packages
    sudo apt-get update && sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade

    # Remove unnecessary packages
    echo "Removing unnecessary packages..."
    sudo apt-get autoremove -y

    # Install necessary security packages
    echo "Installing necessary security packages..."
    sudo apt-get install -y ufw rkhunter chkrootkit fail2ban unattended-upgrades

    # Enable firewall
    echo "Enabling firewall..."
    sudo ufw enable

    # Disable root login over SSH
    echo "Disabling root login over SSH..."
    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd

    # Set strong password policies
    echo "Setting strong password policies..."
    sudo apt-get install libpam-cracklib -y
    sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    echo "password requisite pam_cracklib.so try_first_pass retry=3 minlen=12 difok=3" | sudo tee -a /etc/pam.d/common-password

    # Enforce SSH security settings
    echo "Enforcing SSH security settings..."
    echo -e "\n# Security settings" | sudo tee -a /etc/ssh/sshd_config
    echo "Protocol 2" | sudo tee -a /etc/ssh/sshd_config
    echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config
    echo "LoginGraceTime 30" | sudo tee -a /etc/ssh/sshd_config
    echo "AllowUsers yourusername" | sudo tee -a /etc/ssh/sshd_config  # Replace with actual username
    sudo systemctl restart sshd

    # Run rootkit checks
    echo "Running rootkit checks..."
    sudo rkhunter --check
    sudo chkrootkit

    # Enable unattended upgrades
    echo "Enabling unattended upgrades..."
    sudo dpkg-reconfigure -plow unattended-upgrades
}

# Main function
main() {
    echo "Starting system security analysis..."

    score_security
    fix_issues

    echo "Analysis and remediation complete."
}

# Execute main function
main
