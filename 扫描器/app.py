from flask import Flask, request, render_template, redirect, url_for, session
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import builtwith
from bs4 import BeautifulSoup
import re
import html
import os
from threading import Event
import re
from urllib.parse import urljoin, urlparse
import logging
import json
import subprocess
import dns.resolver

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.secret_key = 'your_secret_key'  # 设置一个安全的密钥
socketio = SocketIO(app)

# 数据库连接
def get_db():
    db = sqlite3.connect('instance/users.db')
    db.row_factory = sqlite3.Row
    return db

# 创建用户表
def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)')
    db.close()

init_db()

# 注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="用户名已存在")
        finally:
            db.close()
    return render_template('register.html')

# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        db.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))  # 修改这里
        else:
            return render_template('login.html', error="用户名或密码错误")
    return render_template('login.html')

# 端口扫描
@app.route('/scan')
def scan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('scan.html')

def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    sock.close()
    return port, result == 0

@socketio.on('start_scan')
def handle_scan(data):
    target = data['target']
    start_port = int(data['start_port'])
    end_port = int(data['end_port'])
    
    open_ports = []
    closed_ports = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in range(start_port, end_port + 1)}
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                emit('port_result', {'port': port, 'status': 'open'})
            else:
                closed_ports.append(port)
                emit('port_result', {'port': port, 'status': 'closed'})
    
    emit('scan_complete', {'open_ports': open_ports, 'closed_ports': closed_ports})

# 目录扫描
@app.route('/dirscan')
def dirscan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dirscan.html')

def scan_directory(url, directory):
    full_url = f"{url}/{directory}"
    response = requests.get(full_url)
    return directory, response.status_code

# 修改 handle_dirscan 函数
stop_event = Event()

@socketio.on('start_dirscan')
def handle_dirscan(data):
    global stop_event
    stop_event.clear()  # 重置停止事件
    target_url = data['target_url']
    use_default = data.get('use_default', False)
    
    try:
        if use_default:
            wordlist = load_default_wordlist()
            print(f"Using default wordlist with {len(wordlist)} entries")
        else:
            wordlist = data['wordlist'].split('\n')
            print(f"Using custom wordlist with {len(wordlist)} entries")
        
        found_directories = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {executor.submit(scan_directory, target_url, directory.strip()): directory.strip() for directory in wordlist}
            for future in as_completed(future_to_dir):
                if stop_event.is_set():
                    print("Scan stopped by user")
                    break
                directory, status_code = future.result()
                print(f"Scanned {directory}: status code {status_code}")
                if status_code == 200:
                    full_url = f"{target_url.rstrip('/')}/{directory}"
                    found_directories.append(full_url)
                    emit('dir_result', {'directory': full_url, 'status_code': status_code})
        
        if stop_event.is_set():
            emit('dirscan_stopped', {'message': '扫描已停止'})
        else:
            print(f"Scan complete. Found {len(found_directories)} directories")
            emit('dirscan_complete', {'found_directories': found_directories})
    except Exception as e:
        print(f"Error in directory scan: {str(e)}")
        emit('dirscan_error', {'error': str(e)})

@socketio.on('stop_dirscan')
def handle_stop_dirscan():
    global stop_event
    stop_event.set()
    print("Stop signal received")

# 指纹探测
@app.route('/fingerprint')
def fingerprint():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('fingerprint.html')

@socketio.on('start_fingerprint')
def handle_fingerprint(data):
    target_url = data['target_url']
    timeout = data.get('timeout', 60)  # 默认超时时间为60秒
    
    logging.debug(f"Starting fingerprint scan for {target_url} with timeout {timeout}")
    
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        dddd_path = os.path.join(current_dir, 'dddd.exe')
        
        logging.debug(f"dddd.exe path: {dddd_path}")
        logging.debug(f"Running command: {dddd_path} -t {target_url}")
        
        process = subprocess.Popen([dddd_path, '-t', target_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=False)
        
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                try:
                    decoded_output = output.decode('gbk').strip()
                except UnicodeDecodeError:
                    decoded_output = output.decode('utf-8', errors='ignore').strip()
                
                logging.debug(f"Raw output: {decoded_output}")
                emit('fingerprint_update', {'output': decoded_output})
        
        rc = process.poll()
        if rc == 0:
            emit('fingerprint_complete', {'message': '扫描完成'})
            logging.debug("Scan completed successfully")
        else:
            stderr_output = process.stderr.read()
            try:
                error_message = stderr_output.decode('gbk')
            except UnicodeDecodeError:
                error_message = stderr_output.decode('utf-8', errors='ignore')
            emit('fingerprint_error', {'error': f'扫描失败: {error_message}'})
            logging.error(f"Scan failed: {error_message}")
    except Exception as e:
        logging.exception("An error occurred during fingerprint scan")
        emit('fingerprint_error', {'error': str(e)})

@socketio.on('stop_fingerprint')
def handle_stop_fingerprint():
    emit('fingerprint_stopped', {'message': '在当前模式下无法停止扫描，请等待扫描完成'})

# 渲染首页
@app.route('/')
def index():
    return render_template('index.html')

# 登出
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

# 新增导航页面
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

def load_default_wordlist():
    wordlist_path = os.path.join(os.path.dirname(__file__), 'default_wordlist.txt')
    with open(wordlist_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# 添加新的路由和函数
@app.route('/vulnscan')
def vulnscan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('vulnscan.html')

@socketio.on('start_vulnscan')
def handle_vulnscan(data):
    target_url = data['target_url']
    scan_type = data['scan_type']
    method = data['method']
    post_data = data.get('post_data', '{}')
    
    logging.debug(f"Starting vulnerability scan for {target_url} with type {scan_type} using {method} method")
    try:
        post_data = json.loads(post_data)  # 将JSON字符串转换为字典
        vulnerabilities = []
        if scan_type == 'xss' or scan_type == 'both':
            xss_vulnerabilities = check_xss(target_url, method, post_data)
            vulnerabilities.extend(xss_vulnerabilities)
            logging.debug(f"XSS vulnerabilities found: {xss_vulnerabilities}")
        
        if scan_type == 'sql' or scan_type == 'both':
            sql_vulnerabilities = check_sql_injection(target_url, method, post_data)
            vulnerabilities.extend(sql_vulnerabilities)
            logging.debug(f"SQL injection vulnerabilities found: {sql_vulnerabilities}")
        
        logging.debug(f"Emitting vulnscan_result with {len(vulnerabilities)} vulnerabilities")
        emit('vulnscan_result', {'vulnerabilities': vulnerabilities})
    except json.JSONDecodeError:
        logging.error("Invalid POST data format")
        emit('vulnscan_error', {'error': "POST数据格式无效,请检查输入"})
    except Exception as e:
        logging.error(f"Error during vulnerability scan: {str(e)}")
        emit('vulnscan_error', {'error': f"扫描过程中发生错误: {str(e)}"})

def check_xss(url, method, post_data):
    payloads = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")'
    ]
    vulnerabilities = []
    try:
        response = requests.get(url)
        parsed_url = urlparse(url)
        
        # 检查URL参数
        if parsed_url.query:
            params = dict(param.split('=') for param in parsed_url.query.split('&'))
            for param, value in params.items():
                for payload in payloads:
                    if method == 'get':
                        test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                        test_response = requests.get(test_url)
                        if payload in test_response.text:
                            vulnerabilities.append(f"可能的XSS漏洞 (GET): {test_url}")
                    else:
                        test_response = requests.post(url, data={param: payload})
                        if payload in test_response.text:
                            vulnerabilities.append(f"可能的XSS漏洞 (POST): {url}, Payload: {payload}")
        
        # 检查表单
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(url, form.get('action', ''))
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    for payload in payloads:
                        data = {input_name: payload}
                        if method == 'post' or (method == 'auto' and form_method == 'post'):
                            test_response = requests.post(action, data=data)
                            if payload in test_response.text:
                                vulnerabilities.append(f"可能的XSS漏洞 (POST): {action}, Payload: {payload}")
                        else:
                            test_url = action + '?' + '&'.join([f"{k}={v}" for k, v in data.items()])
                            test_response = requests.get(test_url)
                            if payload in test_response.text:
                                vulnerabilities.append(f"可能的XSS漏洞 (GET): {test_url}")
    
        if method == 'post' or method == 'auto':
            for payload in payloads:
                test_data = post_data.copy()
                for key in test_data:
                    test_data[key] = payload
                test_response = requests.post(url, data=test_data)
                if payload in test_response.text:
                    vulnerabilities.append(f"可能的XSS漏洞 (POST): {url}, Payload: {payload}")
    
    except Exception as e:
        print(f"XSS检查错误: {str(e)}")
    
    return vulnerabilities

def check_sql_injection(url, method, post_data):
    payloads = [
        "' OR '1'='1",
        '" OR "1"="1',
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        '" UNION SELECT NULL--',
        "1' ORDER BY 1--",
        '1" ORDER BY 1--',
        "1' UNION SELECT @@version--",
        '1" UNION SELECT @@version--'
    ]
    vulnerabilities = []
    try:
        response = requests.get(url)
        parsed_url = urlparse(url)
        
        # 检查URL参数
        if parsed_url.query:
            params = dict(param.split('=') for param in parsed_url.query.split('&'))
            for param, value in params.items():
                for payload in payloads:
                    if method == 'get':
                        test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                        test_response = requests.get(test_url)
                    else:
                        test_response = requests.post(url, data={param: payload})
                    if "error in your SQL syntax" in test_response.text.lower():
                        vulnerabilities.append(f"可能的SQL注入漏洞 ({method.upper()}): {url}, 参数: {param}")
        
        # 检查表单
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = urljoin(url, form.get('action', ''))
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    for payload in payloads:
                        data = {input_name: payload}
                        if method == 'post' or (method == 'auto' and form_method == 'post'):
                            test_response = requests.post(action, data=data)
                        else:
                            test_url = action + '?' + '&'.join([f"{k}={v}" for k, v in data.items()])
                            test_response = requests.get(test_url)
                        if "error in your SQL syntax" in test_response.text.lower():
                            vulnerabilities.append(f"可能的SQL注入漏洞 ({method.upper()}): {action}, 参数: {input_name}")
    
        if method == 'post' or method == 'auto':
            for payload in payloads:
                test_data = post_data.copy()
                for key in test_data:
                    test_data[key] = payload
                test_response = requests.post(url, data=test_data)
                if "error in your SQL syntax" in test_response.text.lower():
                    vulnerabilities.append(f"可能的SQL注入漏洞 (POST): {url}, 数据: {test_data}")
    
    except Exception as e:
        print(f"SQL注入检查错误: {str(e)}")
    
    return vulnerabilities

# 子域名枚举
@app.route('/subdomain')
def subdomain():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('subdomain.html')

# 添加全局变量来控制子域名枚举和爬虫进程
subdomain_stop_event = Event()
crawler_stop_event = Event()

@socketio.on('start_subdomain_enum')
def handle_subdomain_enum(data):
    global subdomain_stop_event
    subdomain_stop_event.clear()
    domain = data['domain']
    subdomains = []
    try:
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4']
        
        for subdomain in common_subdomains:
            if subdomain_stop_event.is_set():
                emit('subdomain_stopped', {'message': '枚举已停止'})
                return
            try:
                host = f"{subdomain}.{domain}"
                answers = dns.resolver.resolve(host, 'A')
                if answers:
                    subdomains.append(host)
                    emit('subdomain_found', {'subdomain': host})
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                pass
        
        emit('subdomain_complete', {'message': '子域名枚举完成', 'count': len(subdomains)})
    except Exception as e:
        emit('subdomain_error', {'error': str(e)})

@socketio.on('stop_subdomain_enum')
def handle_stop_subdomain_enum():
    global subdomain_stop_event
    subdomain_stop_event.set()

# 网站爬虫
@app.route('/crawler')
def crawler():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('crawler.html')

@socketio.on('start_crawl')
def handle_crawl(data):
    global crawler_stop_event
    crawler_stop_event.clear()
    url = data['url']
    max_pages = data.get('max_pages', 100)  # 默认最多爬取100页
    visited = set()
    to_visit = [url]
    
    try:
        while to_visit and len(visited) < max_pages:
            if crawler_stop_event.is_set():
                emit('crawl_stopped', {'message': '爬虫已停止'})
                return
            current_url = to_visit.pop(0)
            if current_url not in visited:
                visited.add(current_url)
                try:
                    response = requests.get(current_url, timeout=5)
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        emit('page_crawled', {'url': current_url, 'title': soup.title.string if soup.title else 'No title'})
                        
                        for link in soup.find_all('a', href=True):
                            absolute_link = urljoin(current_url, link['href'])
                            if urlparse(absolute_link).netloc == urlparse(url).netloc and absolute_link not in visited:
                                to_visit.append(absolute_link)
                except requests.RequestException:
                    pass
        
        emit('crawl_complete', {'message': '爬虫完成', 'pages_crawled': len(visited)})
    except Exception as e:
        emit('crawl_error', {'error': str(e)})

@socketio.on('stop_crawl')
def handle_stop_crawl():
    global crawler_stop_event
    crawler_stop_event.set()

if __name__ == '__main__':
    socketio.run(app, debug=True)
