import time
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string # type: ignore
from datetime import datetime
import threading
import re
import sys
import json
import uuid
import os
import signal
from pathlib import Path
from hashlib import sha256
from colorama import Fore, Style, init # type: ignore
from werkzeug.serving import run_simple # type: ignore
import logging
import random
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

init(autoreset=True)
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

request_logs = []
logs_lock = threading.RLock()
app = Flask(__name__)
app.secret_key = os.urandom(24)

def log_info(message, color=RESET):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{WHITE}[{timestamp}] {color}{message}{RESET}")

def load_or_create_config():
    config_path = Path("C:/NDP-Data/config.json")
    data_dir = Path("C:/NDP-Data")
    data_dir.mkdir(parents=True, exist_ok=True)
    
    default_config = {
        'SECRET_VERIFICATION': "token",
        'ADMIN_PORT': 5020,
        'ADMIN_USERS': {
            'admin': "password"
        }
    }
    
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                if 'ADMIN_USERS' in config:
                    for username, password in config['ADMIN_USERS'].items():
                        if len(password) != 64 or not all(c in '0123456789abcdef' for c in password.lower()):
                            config['ADMIN_USERS'][username] = sha256(password.encode()).hexdigest()
                
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                        
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, ensure_ascii=False, indent=4)
                    
                return config
        except Exception as e:
            log_info(f"配置文件加载失败，将使用默认配置: {RED}{str(e)}{RESET}", RED)
            return default_config
    else:
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=4)
            log_info(f"已在 {CYAN}{config_path}{RESET} 创建默认配置文件", YELLOW)
            return default_config
        except Exception as e:
            log_info(f"无法创建配置文件，将使用默认配置: {RED}{str(e)}{RESET}", RED)
            return default_config

config = load_or_create_config()

app.config.update({
    'SECRET_VERIFICATION': config['SECRET_VERIFICATION'],
    'ENV': 'production',
    'DEBUG': False,
    'TESTING': False,
    'DATA_FILE': str('C:/NDP-Data/data.json'),
    'AUTO_SAVE': True,
    'ADMIN_PORT': config['ADMIN_PORT'],
    'ADMIN_USERS': config['ADMIN_USERS']
})

def load_bans_data():
    data_dir = Path("C:/NDP-Data")
    data_file = data_dir / "data.json"
    
    data_dir.mkdir(parents=True, exist_ok=True)
    
    log_info(f"加载数据文件中, 路径: {CYAN}{data_file}{RESET}", WHITE)
    
    try:
        if data_file.exists():
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                log_info(f"成功加载数据文件 ({len(data['players'])} 玩家|{len(data['ips'])} IP)", GREEN)
                return data
        else:
            initial_data = {
                'ips': {},
                'players': {},
                'history': [],
                'pending': []
            }
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, ensure_ascii=False, indent=4)
            log_info(f"未找到数据文件，已在 {CYAN}{data_file}{RESET} 创建空数据库", YELLOW)
            return initial_data
            
    except Exception as e:
        log_info(f"数据加载失败[已重建]: {RED}{str(e)}{RESET}", RED)
        data_dir.mkdir(parents=True, exist_ok=True)
        initial_data = {
            'ips': {},
            'players': {},
            'history': [],
            'pending': []
        }
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, ensure_ascii=False, indent=4)
        return initial_data

bans = load_bans_data()
data_lock = threading.RLock()
exit_event = threading.Event()

def save_bans_data():
    try:
        with data_lock:
            data_file = Path(app.config['DATA_FILE'])
            with open(data_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'ips': bans['ips'],
                    'players': bans['players'],
                    'history': bans['history'][-1000:],
                    'pending': bans['pending']
                }, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log_info(f"数据保存失败: {str(e)}", RED)

@app.after_request
def log_response(response):
    excluded_paths = ['/static', '/login', '/logout', '/admin/pending']
    if any(request.path.startswith(p) for p in excluded_paths):
        return response
    
    with logs_lock:
        log_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'method': request.method,
            'path': request.path,
            'status': response.status_code,
            'client_ip': request.remote_addr
        }
        request_logs.append(log_data)
    
    return response


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = sha256(request.form.get('password', '').encode()).hexdigest()
        
        if username in app.config['ADMIN_USERS'] and app.config['ADMIN_USERS'][username] == password:
            session['authenticated'] = True
            session['username'] = username
            return redirect(url_for('review_page'))
        return render_template_string('''
            <div style="color: red;">用户名或密码错误</div>
            <a href="/login">返回登录</a>
        ''')
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="zh">
        <head>
            <meta charset="UTF-8">
            <title>NDP 登录系统</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f0f2f5; height: 100vh; display: flex; justify-content: center; align-items: center; }
                .login-box { background: white; width: 400px; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .form-group { margin-bottom: 1.5rem; }
                input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                button { background: #007bff; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; width: 100%; cursor: pointer; }
                .logo { text-align: center; font-size: 1.5rem; color: #333; margin-bottom: 2rem; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <div class="logo">NDP 封禁管理系统</div>
                <form method="post">
                    <div class="form-group">
                        <input type="text" name="username" placeholder="用户名" required>
                    </div>
                    <div class="form-group">
                        <input type="password" name="password" placeholder="密码" required>
                    </div>
                    <button type="submit">登录</button>
                </form>
            </div>
        </body>
        </html>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def login_required(f):
    def wrapper(*args,**kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args,**kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/admin/pending')
@login_required
def get_pending():
    with data_lock:
        return jsonify(bans['pending'])

@app.route('/admin/approve/<id>', methods=['POST'], endpoint='approve_request_post')
@login_required
def approve_request(id):
    with data_lock:
        for i, req in enumerate(bans['pending']):
            if req['id'] == id:
                if req['action'] == 'ban':
                    bans['players'][req['username']] = {
                        'ip': req['ip'], 
                        'cause': req['cause'],
                        'timestamp': datetime.now().isoformat(),
                        'related_ips': [req['ip']]
                    }
                    if req['ip'] not in bans['ips']:
                        bans['ips'][req['ip']] = {
                            'cause': f"关联封禁：{req['username']}",
                            'timestamp': datetime.now().isoformat(),
                            'players': [req['username']]
                        }
                    else:
                        bans['ips'][req['ip']]['players'].append(req['username'])
                    bans['history'].append({
                        'type': '同意封禁',
                        'username': req['username'],
                        'ip': req['ip'],
                        'cause': req['cause'],
                        'timestamp': datetime.now().isoformat()
                    })
                elif req['action'] == 'remove':
                    username = req['username']
                    if username in bans['players']:
                        related_ips = bans['players'][username].get('related_ips', [])
                        del bans['players'][username]
                        for ip in related_ips:
                            if ip in bans['ips'] and username in bans['ips'][ip]['players']:
                                bans['ips'][ip]['players'].remove(username)
                                if not bans['ips'][ip]['players']:
                                    del bans['ips'][ip]
                        bans['history'].append({
                            'type': '解封通过',
                            'username': username,
                            'ip': ', '.join(related_ips),
                            'timestamp': datetime.now().isoformat()
                        })
                    else:
                        bans['history'].append({
                            'type': '解封失败',
                            'username': username,
                            'cause': '该玩家未被封禁',
                            'timestamp': datetime.now().isoformat()
                        })
                        bans['pending'].pop(i)
                        save_bans_data()
                        return jsonify({"error": "该玩家未被封禁"}), 400
                
                bans['pending'].pop(i)
                save_bans_data()
                return jsonify({"status": "success"})
        return jsonify({"error": "Request not found"}), 404
# WebUI
@app.route('/review')
@login_required
def review_page():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="zh">
        <head>
            <meta charset="UTF-8">
            <title>封禁审核系统</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 2rem; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
                .request-card { background: white; padding: 1.5rem; margin-bottom: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .btn { padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; border: none; }
                .btn-approve { background: #28a745; color: white; margin-right: 0.5rem; }
                .btn-reject { background: #dc3545; color: white; }
                .loading { text-align: center; padding: 2rem; color: #666; }
                .request-details {
                    margin: 15px 0;
                    padding: 10px;
                    background: #f8f9fa;
                    border-radius: 6px;
                }

                .request-details p {
                    margin: 8px 0;
                    color: #666;
                }

                .action-buttons {
                    margin-top: 15px;
                    display: flex;
                    gap: 10px;
                }

                .btn-approve {
                    background: #28a745 !important;
                }

                .btn-reject {
                    background: #dc3545 !important;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>待审核请求 (<span id="count">0</span>)</h1>
                    <div>
                        <span style="margin-right: 1rem;">欢迎, {{ session.username }}</span>
                        <a href="/logout" class="btn">退出登录</a>
                    </div>
                </div>
                <div id="requests" class="requests-list">
                    <div class="loading">加载中...</div>
                </div>
            </div>
            <script>
                async function fetchData() {
                    try {
                        const res = await fetch('/admin/pending');
                        const data = await res.json();
                        
                        document.getElementById('count').textContent = data.length;
                        
                        const html = data.map(req => `
                            <div class="request-card">
                                <h3>${req.action === 'ban' ? '封禁请求' : '解封请求'} - ${req.username}</h3>
                                <div class="request-details">
                                    <p><strong>操作类型:</strong> ${req.action === 'ban' ? '封禁' : '解封'}</p>
                                    <p><strong>IP地址:</strong> ${req.ip}</p>
                                    <p><strong>申请理由:</strong> ${req.cause}</p>
                                    <p><strong>提交时间:</strong> ${new Date(req.timestamp).toLocaleString()}</p>
                                </div>
                           <div class="action-buttons">
                               <button class="btn btn-approve" 
                                       onclick="handleAction('${req.id}', 'approve')">
                                           ${req.action === 'ban' ? '通过封禁' : '通过解封'}
                                       </button>
                                       <button class="btn btn-reject" 
                                               onclick="handleAction('${req.id}', 'reject')">
                                           拒绝${req.action === 'ban' ? '封禁' : '解封'}
                                       </button>
                           </div>
                       </div>
                        `).join('');
                        
                        document.getElementById('requests').innerHTML = html || '<div class="loading">暂无待审核请求</div>';
                    } catch (error) {
                        console.error('请求失败:', error);
                    }
                }

                async function handleAction(id, type) {
    try {
        const endpoint = type === 'approve' ? 'approve' : 'reject';
        const response = await fetch(`/admin/${endpoint}/${id}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.status === "success") {
                fetchData(); 
            } else {
                alert('操作失败: ' + (result.error || '未知错误'));
            }
        } else {
            const errorText = await response.text();
            if (errorText.startsWith('<!doctype')) {
                alert('服务器返回了错误页面，请检查控制台');
                console.error('服务器错误:', errorText);
            } else {
                try {
                    const errorData = JSON.parse(errorText);
                    alert('操作失败: ' + (errorData.error || '未知错误'));
                } catch {
                    alert('网络错误: ' + errorText);
                }
            }
        }
    } catch (error) {
        alert('网络请求失败: ' + error.message);
    }
}

                setInterval(fetchData, 5000);
                fetchData();
            </script>
        </body>
        </html>
    ''')

# API
@app.route('/admin/reject/<id>', methods=['POST'], endpoint='reject_request_post')
@login_required
def reject_request(id):
    with data_lock:
        for i, req in enumerate(bans['pending']):
            if req['id'] == id:
                bans['history'].append({
                    'type': '拒绝封禁' if req['action'] == 'ban' else '拒绝解封',
                    'username': req['username'],
                    'ip': req['ip'],
                    'cause': req['cause'],
                    'timestamp': datetime.now().isoformat()
                })
                bans['pending'].pop(i)
                save_bans_data()
                return jsonify({"status": "success"})
        return jsonify({"error": "Request not found"}), 404
@app.route('/add_ban', methods=['POST'])
def handle_ban_request():
    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400
    
    data = request.get_json()
    required_fields = ['verification', 'action', 'username', 'ip', 'cause']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing parameters"}), 400
    
    if data['verification'] != app.config['SECRET_VERIFICATION']:
        return jsonify({"error": "Authentication failed"}), 403
    if data['action'] not in ['ban', 'remove']:
        return jsonify({"error": "Invalid action type"}), 400

    request_id = str(uuid.uuid4())
    pending_request = {
        'id': request_id,
        'action': data['action'],
        'username': data['username'].strip(),
        'ip': data['ip'].split(':')[0],
        'cause': data['cause'],
        'timestamp': datetime.now().isoformat(),
        'source_ip': request.remote_addr
    }
    
    with data_lock:
        bans['pending'].append(pending_request)
        save_bans_data()
    
    return jsonify({
        "status": "pending_review",
        "request_id": request_id
    }), 202
#TEST
@app.route('/test', methods=['GET'])
def test_endpoint():
    with data_lock:
        test_data = {
        "status": "running"
        }
    return jsonify(test_data)
#banlist api
@app.route('/bans', methods=['GET'])
def get_bans():
    verification = request.args.get('verification')
    with data_lock:
        current_players = [
            {
                "username": username,
                "ip": data['ip'],
                "cause": data['cause'],
                "timestamp": data['timestamp']
            } for username, data in bans['players'].items()
        ]
        
        current_ips = [
            {
                "ip": ip,
                "cause": data['cause'],
                "players": data['players'],
                "timestamp": data['timestamp']
            } for ip, data in bans['ips'].items()
        ]
        
        return jsonify({
            "action": "list",
            "ip_count": len(bans['ips']),
            "player_count": len(bans['players']),
            "active_players": current_players,
            "active_ips": current_ips
        })

@app.route('/check_ban', methods=['GET'])
def check_ban():
    username = request.args.get('username', '')
    ip = request.args.get('ip', '').split(':')[0]  
    
    with data_lock:
        timestamp = datetime.now().isoformat()
        if ip and ip in bans['ips']:
            ip_data = bans['ips'][ip]
            return jsonify({
                "action": "kick",
                "cause": ip_data['cause'],
                "info": {
                    "related_players": ip_data['players'],
                    "ban_type": "ip"
                }
            })
        if username and username in bans['players']:
            player_data = bans['players'][username]
            return jsonify({
                "action": "kick",
                "cause": player_data['cause'],
                "ip": player_data['ip'],
                "info": {
                    "related_ips": player_data['related_ips'],
                    "ban_type": "player"
                }
            })
        return jsonify({
            "action": "allowed",
            "status": "clean",
            "timestamp": timestamp
        })

# CLI
def command_line_interface():
    help_text = f"""{CYAN}
NDP 控制台
{'-'*40}
{WHITE}命令列表：{RESET}
{WHITE}ban {YELLOW}<用户名> <IP> <原因>{RESET}   {CYAN}-添加封禁请求
{WHITE}pardon {YELLOW}<用户名>{RESET}            {CYAN}-解除玩家封禁
{WHITE}stats{RESET}                      {CYAN}-显示系统统计
{WHITE}history {YELLOW}[数量]{RESET}             {CYAN}-查看操作历史
{WHITE}logs{RESET}                    {CYAN}-列出所有日志
{WHITE}banlist{RESET}                    {CYAN}-列出所有封禁玩家
{WHITE}help{RESET}                       {CYAN}-显示帮助信息
{WHITE}reload {YELLOW}[data|config|all]{RESET}    {CYAN}-重载数据或配置
{WHITE}exit{RESET}                       {CYAN}-退出
"""
    print(help_text)
    
    while True:
        try:
            cmd_input = sys.stdin.readline().strip()
            if not cmd_input:
                print(f"{GREEN}NDP> {RESET}", end='', flush=True)
                continue
            
            cmd = cmd_input.split()
            if not cmd: 
                continue

            print(f"{GREEN}NDP> {RESET}", end='', flush=True)

            if cmd[0] == 'ban':
                if len(cmd) < 2:
                    print(f"{RED}错误: 参数不足，用法: ban <用户名> <IP> <原因>{RESET}")
                    continue
                    
                username, ip, cause = cmd[1], cmd[2], ' '.join(cmd[3:])
                if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip.split(':')[0]):
                    print(f"{RED}错误：无效的IP地址{RESET}")
                    continue
                
                with data_lock:
                    timestamp = datetime.now().isoformat()
                    bans['players'][username] = {
                        'ip': ip,
                        'cause': cause,
                        'timestamp': timestamp,
                        'related_ips': [ip]
                    }
                    if ip not in bans['ips']:
                        bans['ips'][ip] = {
                            'cause': f"关联封禁：{username}",
                            'timestamp': timestamp,
                            'players': [username]
                        }
                    else:
                        bans['ips'][ip]['players'].append(username)
                    bans['history'].append({
                        'type': 'ban',
                        'username': username,
                        'ip': ip,
                        'cause': cause,
                        'timestamp': timestamp
                    })
                    save_bans_data()
                print(f"{GREEN}成功封禁：{username}@{ip}{RESET}")
                print(f"{CYAN}当前封禁总数: {len(bans['players'])} 玩家 | {len(bans['ips'])} IP{RESET}")

            elif cmd[0] == 'pardon':
                if len(cmd) < 2:
                    print(f"{RED}错误: 参数不足，用法: pardon <用户名>{RESET}")
                    continue
                    
                username = cmd[1]
                with data_lock:
                    if username in bans['players']:
                        ip = bans['players'][username]['ip']
                        del bans['players'][username]
                        if ip in bans['ips']:
                            bans['ips'][ip]['players'].remove(username)
                            if not bans['ips'][ip]['players']:
                                del bans['ips'][ip]
                        save_bans_data()
                        print(f"{GREEN}成功解封：{username}{RESET}")
                    else:
                        print(f"{YELLOW}未找到用户：{username}{RESET}")
                        continue

            elif cmd[0] == 'stats':
                with data_lock:
                    print(f"\n{CYAN}系统统计{RESET}")
                    print(f"{BLUE}已封禁IP：{len(bans['ips'])} 个")
                    print(f"{BLUE}已封禁玩家：{len(bans['players'])} 人")
                    print(f"{BLUE}待审核请求：{len(bans['pending'])} 条{RESET}")
                    continue

            elif cmd[0] == 'banlist':
                with data_lock:
                    if not bans['players']:
                        print(f"{YELLOW}当前没有封禁玩家{RESET}")
                        continue
                    
                    print(f"\n{CYAN}封禁玩家列表 (共 {len(bans['players'])} 人){RESET}")
                    print(f"{WHITE}{'用户名':<20}{'IP地址':<20}{'封禁时间':<25}{'封禁原因'}{RESET}")
                    print("-" * 80)
                    for username, data in bans['players'].items():
                        timestamp = datetime.fromisoformat(data['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                        print(f"{YELLOW}{username:<20}{WHITE}{data['ip']:<20}{CYAN}{timestamp:<25}{BLUE}{data['cause']}{RESET}")
                    print("-" * 80)
                    continue

            elif cmd[0] == 'history':
                try:
                    limit = min(int(cmd[1]), 50) if len(cmd) > 1 else 5
                except ValueError:
                    print(f"{RED}错误: 数量参数必须是数字{RESET}")
                    continue
                    
                with data_lock:
                    print(f"\n{CYAN}最近{limit}条记录{RESET}")
                    for entry in reversed(bans['history'][-limit:]):
                        time_str = entry['timestamp'][11:19]
                        print(f"{YELLOW}[{time_str}] {entry['type'].upper()} {entry['username']}")
                        print(f"{BLUE}原因：{entry['cause']}{RESET}")
                        continue

            elif cmd[0] == 'help':
                print(help_text)
                
            elif cmd[0] == 'logs':
                print(f"\n{WHITE}系统运行日志{RESET}")
                print(f"{GREEN}数据文件: {CYAN}{Path(app.config['DATA_FILE']).absolute()}{RESET}")
                print(f"{GREEN}网页面板: {CYAN}http://0.0.0.0:{app.config['ADMIN_PORT']}/login{RESET}")
                print(f"{GREEN}API端点: {CYAN}0.0.0.0:{app.config['ADMIN_PORT']}{RESET}")
                print(f"{GREEN}封禁统计: 玩家({CYAN}{len(bans['players'])}{GREEN}) IP({CYAN}{len(bans['ips'])}{GREEN}){RESET}")
                print(f"{GREEN}待审请求: {CYAN}{len(bans['pending'])}{RESET}")
                print(f"\n{WHITE}网络请求记录{RESET}")
                with logs_lock:
                    for log_entry in request_logs[-50:]:
                        status_color = {
                            2: GREEN,
                            3: BLUE,
                            4: YELLOW,
                            5: RED
                        }.get(log_entry['status'] // 100, WHITE)
                        
                        print(
                            f"{WHITE}[{log_entry['timestamp']}] "
                            f"{status_color}{log_entry['method']} "
                            f"{log_entry['path']} {log_entry['status']} "
                            f"{CYAN}[IP: {log_entry['client_ip']}]{RESET}"
                        )
                continue

            elif cmd[0] == 'reload':
                if len(cmd) < 2:
                    print(f"{RED}错误: 参数不足，用法: reload [data|config|all]{RESET}")
                    continue
                    
                option = cmd[1].lower()
                if option not in ['data', 'config', 'all']:
                    print(f"{RED}错误: 无效参数，必须是 data, config 或 all{RESET}")
                    continue
                
                try:
                    if option in ['data', 'all']:
                        print(f"{CYAN}正在重载数据文件...{RESET}")
                        with data_lock:
                            try:
                                new_data = load_bans_data()
                                bans = new_data
                                print(f"{GREEN}数据文件重载成功{RESET}")
                            except Exception as e:
                                print(f"{RED}数据文件重载失败，正在重建...{RESET}")
                                bans = load_bans_data()  # 这会自动重建
                                print(f"{GREEN}数据文件已重建{RESET}")
                    
                    if option in ['config', 'all']:
                        print(f"{CYAN}正在重载配置文件...{RESET}")
                        global config
                        try:
                            new_config = load_or_create_config()
                            config = new_config
                            # 更新app配置
                            app.config.update({
                                'SECRET_VERIFICATION': config['SECRET_VERIFICATION'],
                                'ADMIN_PORT': config['ADMIN_PORT'],
                                'ADMIN_USERS': config['ADMIN_USERS']
                            })
                            print(f"{GREEN}配置文件重载成功{RESET}")
                        except Exception as e:
                            print(f"{RED}配置文件重载失败，正在重建...{RESET}")
                            config = load_or_create_config()  # 这会自动重建
                            # 更新app配置
                            app.config.update({
                                'SECRET_VERIFICATION': config['SECRET_VERIFICATION'],
                                'ADMIN_PORT': config['ADMIN_PORT'],
                                'ADMIN_USERS': config['ADMIN_USERS']
                            })
                            print(f"{GREEN}配置文件已重建{RESET}")
                    
                    print(f"{GREEN}重载操作完成{RESET}")
                    
                except Exception as e:
                    print(f"{RED}重载过程中发生错误: {str(e)}{RESET}")
                    continue
                
            elif cmd[0] == 'exit':
                print(f"{CYAN}正在关闭服务...{RESET}")
                os.kill(os.getpid(), signal.SIGINT)
                sys.exit(0)
                
            else:
                print(f"{RED}错误:未知命令 '{cmd[0]}',输入 help 查看可用命令{RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{RED}正在关闭服务...{RESET}")
            os.kill(os.getpid(), signal.SIGINT)
        except Exception as e:
            log_info(f"命令执行错误: {str(e)}", RED)
def signal_handler(sig, frame):
    print(f"\n{CYAN}正在关闭服务...{RESET}")
    sys.exit(0)
if __name__ == '__main__':
    version=(8.5)
    signal.signal(signal.SIGINT, signal_handler)    
    print(rf"""{WHITE}
    _   ______  ____     _____                          
   / | / / __ \/ __ \   / ___/___  ______   _____  _____
  /  |/ / / / / /_/ /   \__ \/ _ \/ ___/ | / / _ \/ ___/
 / /|  / /_/ / ____/   ___/ /  __/ /   | |/ /  __/ /    
/_/ |_/_____/_/       /____/\___/_/    |___/\___/_/     

 + Copyright 2025 Codewaves <https://ndp.codewaves.cn>
 + By EXE_autumnwind 
 + Version {version}.0                                                                            
{RESET}""")
    log_info(f"欢迎使用NDP Server CLI控制台",WHITE)
    data_path = Path(app.config['DATA_FILE']).absolute()
    config_path = Path("C:/NDP-Data/config.json").absolute()
    log_info(f"{GREEN}配置文件位置: {CYAN}{config_path}{RESET}")
    log_info(f"{GREEN}数据文件位置: {CYAN}{data_path}{RESET}")
    log_info(f"{GREEN}网页服务: {CYAN}http://0.0.0.0:{app.config['ADMIN_PORT']}/login") 
    log_info(f"{GREEN}API服务运行于 {CYAN}0.0.0.0:{app.config['ADMIN_PORT']}")
    log_info(f"当前封禁数据状态：", WHITE)
    log_info(f"玩家封禁数: {CYAN}{len(bans['players'])}{RESET} | IP封禁数: {CYAN}{len(bans['ips'])}{RESET}")
    log_info(f"历史记录数: {CYAN}{len(bans['history'])}{RESET} | 待审核请求: {CYAN}{len(bans['pending'])}{RESET}")  
    cli_thread = threading.Thread(target=command_line_interface, daemon=True)
    cli_thread.start()
    try:
        run_simple(
            '0.0.0.0', 
            app.config['ADMIN_PORT'], 
            app, 
            use_reloader=False,  
            threaded=True
        )
    except KeyboardInterrupt:
        print(f"{CYAN}已停止运行{RESET}")
