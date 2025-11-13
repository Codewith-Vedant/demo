# Implementation of Damn Vulnerable Web Applications (DVWA) on Ubuntu with VirtualBox

## Aim

To install VirtualBox on an existing Ubuntu machine (bare metal), create and configure an Ubuntu virtual machine inside VirtualBox, and then install DVWA on that guest Ubuntu VM for practicing web application security testing in a fully isolated environment.

## Theory

### Scenario Overview
You already have Ubuntu installed directly on your computer. You want to:
1. Install VirtualBox application on your Ubuntu system
2. Create a new virtual Ubuntu machine inside VirtualBox
3. Install and configure DVWA on that virtual Ubuntu machine

This creates a **nested virtualization** scenario:
- **Host OS**: Ubuntu (running on your hardware)
- **Hypervisor**: VirtualBox (software that manages virtual machines)
- **Guest OS**: Ubuntu (running inside VirtualBox)
- **Application**: DVWA (running on the guest Ubuntu)

### Why This Approach?
Even though you have Ubuntu, using VirtualBox allows you to:
- Keep DVWA completely isolated from your main system
- Easily create snapshots and reset the vulnerable environment
- Protect your main Ubuntu installation
- Have complete control over the vulnerable machine
- Share DVWA machines across different systems

### Components
- **VirtualBox**: Free, open-source virtualization software
- **LAMP Stack**: Linux (guest OS) + Apache + MariaDB/MySQL + PHP
- **DVWA**: Intentionally vulnerable PHP web application for learning

## Prerequisites

Before starting, ensure you have:
- Ubuntu system running and user with sudo access
- At least 50GB free disk space on main Ubuntu drive (20GB for VM + 30GB buffer)
- At least 8GB total RAM (4GB for host, 4GB for guest VM)
- Internet connection
- Basic terminal familiarity

## Procedure

### Step 1: Update Ubuntu System

Open terminal on your Ubuntu machine and run:

```bash
sudo apt update
sudo apt upgrade -y
```

### Step 2: Install VirtualBox on Ubuntu Host

**Option A: Install from Ubuntu Repository (Easiest)**

```bash
sudo apt install virtualbox virtualbox-ext-pack -y
```

**Option B: Install Latest Version from Oracle Repository**

```bash
# Add Oracle's GPG key
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -

# Add VirtualBox repository
echo "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -sc) contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list

# Update and install
sudo apt update
sudo apt install virtualbox-7.0 virtualbox-ext-pack -y
```

### Step 3: Accept VirtualBox License

When installing ext-pack, you may see a license dialog. Read and accept by pressing Tab and then Enter.

### Step 4: Launch VirtualBox

```bash
virtualbox &
```

Or find VirtualBox in your applications menu and click to open.

### Step 5: Download Ubuntu ISO for Guest VM

Download Ubuntu 22.04 LTS ISO file from:
```
https://ubuntu.com/download/desktop
```

Save the ISO file (approximately 6GB) to your home directory or a known location.

### Step 6: Create New Virtual Machine in VirtualBox

1. Click **"New"** button in VirtualBox
2. Enter name: `DVWA-Lab` or any name
3. Machine Folder: Keep default
4. ISO Image: Click folder icon and select the Ubuntu ISO you downloaded
5. Click **"Next"**

### Step 7: Configure VM Hardware

1. **Base Memory**: Set to **4096 MB** (4GB)
2. **Processors**: Set to **2** cores
3. Click **"Next"**

### Step 8: Create Virtual Hard Disk

1. **Create a Virtual Hard Disk Now**: Selected by default
2. Click **"Next"**
3. **Disk Type**: Choose `VDI (VirtualBox Disk Image)` - keep default
4. Click **"Next"**
5. **Storage**: Choose `Dynamically allocated`
6. Click **"Next"**
7. **File Size**: Set to `30 GB`
8. Click **"Finish"**

VirtualBox will create the virtual machine.

### Step 9: Start the Virtual Machine

1. Select the `DVWA-Lab` VM from the list
2. Click **"Start"** (green arrow)
3. The VM will boot from the Ubuntu ISO

### Step 10: Install Ubuntu on Guest VM

1. Select language: **English**
2. Select keyboard layout
3. Click **"Install Ubuntu"**
4. Choose installation type: **Normal installation**
5. Tick: "Download updates while installing Ubuntu"
6. Tick: "Install third-party software for graphics and WiFi hardware"
7. Choose **"Erase disk and install Ubuntu"** (this only affects the virtual disk, not your main Ubuntu)
8. Click **"Continue"** when warned
9. Select timezone
10. Create user account:
    - Your name: `dvwa-user` (or your preferred name)
    - Computer name: `dvwa-machine`
    - Username: `dvwauser`
    - Password: `dvwa123` (or any password you remember)
    - Tick: **"Require my password to log in"**
11. Click **"Continue"** and wait for installation (10-20 minutes)
12. Click **"Restart Now"** when installation completes

### Step 11: Boot Guest Ubuntu VM

Guest Ubuntu will restart inside VirtualBox. Login with credentials you created.

### Step 12: Update Guest Ubuntu System

Open Terminal in the guest Ubuntu and run:

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 13: Install LAMP Stack on Guest Ubuntu

Install all required packages:

```bash
sudo apt install apache2 mariadb-server php php-mysqli php-gd php-xml php-mbstring php-curl git unzip wget -y
```

### Step 14: Start Services on Guest

```bash
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### Step 15: Configure MariaDB Database

```bash
sudo mysql -u root << EOF
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;
EOF
```

### Step 16: Download DVWA Source Code

```bash
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo mv DVWA dvwa
sudo chown -r www-data:www-data dvwa
sudo chmod -R 755 dvwa
```

### Step 17: Configure DVWA Config File

```bash
cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php
sudo nano config.inc.php
```

Find and edit these lines:
```php
$_DVWA[ 'db_user' ] = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa';
$_DVWA[ 'db_host' ] = 'localhost';
```

Press `Ctrl + X`, then `Y`, then `Enter` to save.

### Step 18: Configure PHP Settings

Find PHP version:
```bash
php -v
```

Example output: `PHP 8.1.2`

Edit php.ini for your version (replace 8.1 with your version if different):
```bash
sudo nano /etc/php/8.1/apache2/php.ini
```

Search for `allow_url_include` (use Ctrl+W in nano):
```
allow_url_include = On
```

Change from `Off` to `On`

Save: `Ctrl + X`, then `Y`, then `Enter`

### Step 19: Restart Apache

```bash
sudo systemctl restart apache2
```

### Step 20: Initialize DVWA Database

Open web browser in guest Ubuntu and go to:
```
http://localhost/dvwa/setup.php
```

Click button: **"Create / Reset Database"**

You should see success message.

### Step 21: Login to DVWA

Navigate to:
```
http://localhost/dvwa
```

Default credentials:
- **Username**: `admin`
- **Password**: `password`

Click **Login**

Congratulations! DVWA is now running!

## Expected Outcomes

After completing these steps, you should have:

1. **VirtualBox Installed**: Running on your main Ubuntu machine
2. **Guest Ubuntu VM**: A complete isolated Ubuntu system running inside VirtualBox with 30GB disk and 4GB RAM
3. **LAMP Stack Configured**: Apache, MariaDB, and PHP working on guest Ubuntu
4. **DVWA Running**: Accessible at `http://localhost/dvwa` on the guest machine
5. **Database Created**: MariaDB with dvwa database and user configured
6. **Successful Login**: Able to log in with admin/password credentials
7. **Security Levels Available**: Can switch between Low/Medium/High/Impossible levels
8. **Vulnerability Labs Ready**: All practice scenarios available including SQL Injection, XSS, CSRF, etc.

## Conclusion

You now have a complete, isolated DVWA lab environment running on your Ubuntu system using VirtualBox. The guest Ubuntu machine is completely separate from your host system, ensuring full isolation and safety. Any malware or issues in the guest cannot affect your host Ubuntu.

**Key Benefits:**
- **Isolation**: DVWA is completely separated from host OS
- **Snapshots**: Can take snapshots before testing and restore instantly
- **Portability**: Can backup the VM and move to other systems
- **Multiple VMs**: Can create multiple copies for different scenarios
- **Safe Testing**: Experiment freely without affecting production system

**Security Note:**
Keep this DVWA machine isolated. Do not connect it to external networks for practice. Use network isolation features in VirtualBox (NAT mode) to prevent accidental exposure.

## Important Download Links

- VirtualBox Official: https://www.virtualbox.org/wiki/Downloads
- Ubuntu Desktop: https://ubuntu.com/download/desktop
- DVWA GitHub: https://github.com/digininja/DVWA
- DVWA Documentation: https://github.com/digininja/DVWA/wiki

## Troubleshooting

**VirtualBox won't start VM:**
- Ensure virtualization is enabled in BIOS (usually enabled by default on Ubuntu)
- Check system RAM availability

**DVWA database not creating:**
- Verify MariaDB is running: `sudo systemctl status mariadb`
- Check if dvwa user exists: `sudo mysql -u root`

**PHP allow_url_include not working:**
- Verify changes saved to php.ini
- Restart Apache: `sudo systemctl restart apache2`
- Check Apache error log: `sudo tail -f /var/log/apache2/error.log`

**Can't access http://localhost/dvwa:**
- Check Apache is running: `sudo systemctl status apache2`
- Verify DVWA folder exists: `ls -la /var/www/html/dvwa`
- Check permissions: `sudo chown -R www-data:www-data /var/www/html/dvwa`
