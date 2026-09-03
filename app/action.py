import os
import re
import json
import hashlib
import base64
from typing import Tuple

import requests
import urllib3

from app import log

urllib3.disable_warnings()


def solve_cap_challenge(login_url: str, max_retries: int = 2) -> str:
    """
    使用 Playwright 模拟浏览器自动完成 Cap.js 验证并返回 cap_token
    支持重试机制，提高成功率
    """
    for attempt in range(max_retries + 1):
        try:
            from playwright.sync_api import sync_playwright
            
            if attempt > 0:
                log.info(f'第 {attempt + 1} 次重试 Cap.js 验证...')
            
            log.info(f'使用 Playwright 访问登录页面：{login_url}')
            
            with sync_playwright() as p:
                # 启动无头浏览器
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                # 访问登录页面
                page.goto(login_url)
                
                # 等待 Cap.js widget 加载
                log.info('等待 Cap.js widget 加载...')
                page.wait_for_selector('cap-widget', timeout=10000)
                
                # 等待 Cap.js 完成验证（最多等待 60 秒）
                log.info('等待 Cap.js 自动完成验证...')
                
                # 监听 Cap.js 的 solve 事件，获取 cap_token
                cap_token = None
                
                def handle_solve(event):
                    nonlocal cap_token
                    cap_token = event.detail.get('token', '')
                    log.info(f'Cap.js 验证完成，获取到 cap_token')
                
                # 注入脚本来监听 Cap.js 事件
                page.evaluate('''() => {
                    const widget = document.querySelector('cap-widget');
                    if (widget) {
                        widget.addEventListener('solve', (e) => {
                            window.capToken = e.detail.token;
                        });
                    }
                }''')
                
                # 等待 cap_token 被设置
                for i in range(60):  # 最多等待 60 秒
                    cap_token = page.evaluate('() => window.capToken')
                    if cap_token:
                        break
                    import time
                    time.sleep(1)
                
                browser.close()
                
                if cap_token:
                    log.info(f'成功获取 cap_token: {cap_token[:20]}...')
                    return cap_token
                else:
                    log.warning('Cap.js 验证超时，未能获取 cap_token')
                    if attempt < max_retries:
                        log.info(f'将在 3 秒后进行第 {attempt + 2} 次重试...')
                        import time
                        time.sleep(3)
                    continue
            
        except ImportError:
            log.warning('playwright 未安装，无法使用浏览器自动求解 Cap.js')
            return ''
        except Exception as e:
            log.warning(f'Playwright 自动求解 Cap.js 异常：{e}')
            import traceback
            log.warning(traceback.format_exc())
            if attempt < max_retries:
                log.info(f'将在 3 秒后进行第 {attempt + 2} 次重试...')
                import time
                time.sleep(3)
                continue
            return ''
    
    log.warning(f'经过 {max_retries + 1} 次尝试，Cap.js 验证均失败')
    return ''


class Action:
    def __init__(self, email: str, passwd: str, code: str = '', host: str = 'cordcloud.us',
                 device_code: str = '', device_token: str = '', device_fingerprint: str = '',
                 imap_host: str = '', imap_port: int = 993, imap_user: str = '', imap_password: str = '',
                 imap_timeout: int = 120, cap_token: str = ''):
        self.email = email
        self.passwd = passwd
        self.code = code
        self.host = host.replace('https://', '').replace('http://', '').strip()
        self.session = requests.session()
        self.timeout = 6
        self.device_code = device_code
        self.device_token = device_token
        self.device_fingerprint = self._build_fingerprint(device_fingerprint)
        self.cap_token = cap_token
        self.imap_host = imap_host
        self.imap_port = imap_port
        self.imap_user = imap_user
        self.imap_password = imap_password
        self.imap_timeout = imap_timeout

    def format_url(self, path) -> str:
        return f'https://{self.host}/{path}'

    def _build_fingerprint(self, fp: str) -> str:
        """
        生成稳定的设备指纹（32 位十六进制，与浏览器 FingerprintJS visitorId 格式一致）
        指纹恒定 => 服务器识别为同一设备，验证一次后永不过期
        """
        if fp:
            return fp[:32]
        return hashlib.sha256(f"CordCloud-Bot-{self.email}".encode()).hexdigest()[:32]

    @staticmethod
    def _token_file() -> str:
        return os.path.join(os.getcwd(), '.cordcloud_device_token')

    def _load_token(self) -> str:
        try:
            with open(self._token_file(), 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception:
            return ''

    def _save_token(self, token: str) -> None:
        try:
            with open(self._token_file(), 'w', encoding='utf-8') as f:
                f.write(token)
            log.info('已保存待验证 token 到本地文件')
        except Exception as e:
            log.warning(f'保存待验证 token 到本地文件失败：{e}')

    def _clear_token(self) -> None:
        try:
            if os.path.exists(self._token_file()):
                os.remove(self._token_file())
                log.info('设备验证成功，已清除本地保存的 token')
        except Exception as e:
            log.warning(f'清除本地 token 失败：{e}')

    def _default_imap_host(self) -> str:
        domain = self.email.split('@')[-1].lower()
        mapping = {
            'gmail.com': 'imap.gmail.com',
            'googlemail.com': 'imap.gmail.com',
            'outlook.com': 'outlook.office365.com',
            'hotmail.com': 'outlook.office365.com',
            'live.com': 'outlook.office365.com',
            'office365.com': 'outlook.office365.com',
            'qq.com': 'imap.qq.com',
            'foxmail.com': 'imap.qq.com',
            '163.com': 'imap.163.com',
            '126.com': 'imap.126.com',
            'yeah.net': 'imap.yeah.net',
        }
        return mapping.get(domain, '')

    def _auto_code(self, min_uid: int = -1) -> str:
        """未提供 device_code 时，若配置了 IMAP 则自动从邮箱读取验证码"""
        if not self.imap_password:
            return ''
        return self._fetch_email_code(timeout=self.imap_timeout, min_uid=min_uid)

    def _latest_uid(self) -> int:
        """获取邮箱当前最新邮件的 UID，作为区分“验证触发后新到邮件”的基线"""
        try:
            import imaplib
            host = self.imap_host or self._default_imap_host()
            if not host:
                return -1
            user = self.imap_user or self.email
            conn = imaplib.IMAP4_SSL(host, self.imap_port or 993)
            conn.login(user, self.imap_password)
            conn.select('INBOX')
            typ, data = conn.uid('search', None, 'ALL')
            uids = data[0].split()
            conn.logout()
            return int(uids[-1]) if uids else -1
        except Exception as e:
            log.warning(f'获取邮箱最新邮件 UID 失败（将退化为读取最新邮件）：{e}')
            return -1

    def _fetch_email_code(self, timeout: int = 120, min_uid: int = -1) -> str:
        """通过 IMAP 轮询邮箱，提取 CordCloud 发送的验证码。

        min_uid：只接受 UID 大于该值（即验证触发后才新到）的邮件，
        避免在验证码邮件尚未到达时，误读历史邮件中的旧验证码。
        """
        import imaplib
        import email as email_lib
        import time

        host = self.imap_host or self._default_imap_host()
        if not host:
            log.warning('无法自动识别 IMAP 服务器，请在 imap_host 中手动指定')
            return ''
        user = self.imap_user or self.email
        port = self.imap_port or 993

        log.info(f'尝试从邮箱 {user} 自动读取验证码（IMAP {host}:{port}，最多等待 {timeout} 秒）'
                 + (f'，只接受 UID 大于 {min_uid} 的新邮件' if min_uid > 0 else ''))
        deadline = time.time() + timeout
        reported_error = False
        skipped_old = False
        while time.time() < deadline:
            try:
                conn = imaplib.IMAP4_SSL(host, port)
                conn.login(user, self.imap_password)
                conn.select('INBOX')
                typ, data = conn.uid('search', None, 'ALL')
                uids = data[0].split()
                for uid in reversed(uids[-15:]):
                    uid_num = int(uid)
                    typ, msg_data = conn.uid('fetch', uid, '(RFC822)')
                    msg = email_lib.message_from_bytes(msg_data[0][1])
                    subject = self._decode_header(msg.get('Subject', ''))
                    body = self._get_body(msg)
                    sender = self._decode_header(msg.get('From', ''))
                    text = f'{sender}\n{subject}\n{body}'
                    if not self._is_verify_email(text):
                        continue
                    code = self._extract_code(text)
                    if not code:
                        continue
                    if min_uid > 0 and uid_num <= min_uid:
                        # 这是验证触发前就已存在的旧验证码，忽略并等待新邮件
                        if not skipped_old:
                            log.info('发现邮箱中验证触发前已存在的旧验证码邮件，等待新验证码邮件到达')
                            skipped_old = True
                        continue
                    conn.logout()
                    log.info(f'已从邮箱 {user} 读取到验证码：{code}')
                    return code
                conn.logout()
                reported_error = False
            except Exception as e:
                if not reported_error:
                    log.warning(f'读取邮箱验证码异常（稍后自动重试）：{e}')
                    reported_error = True
            time.sleep(5)
        log.warning(f'在 {timeout} 秒内未从邮箱读取到新验证码')
        return ''

    @staticmethod
    def _decode_header(value: str) -> str:
        from email.header import decode_header
        parts = decode_header(value)
        out = ''
        for text, enc in parts:
            if isinstance(text, bytes):
                out += text.decode(enc or 'utf-8', errors='ignore')
            else:
                out += text
        return out

    @staticmethod
    def _get_body(msg) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(errors='ignore')
            return ''
        payload = msg.get_payload(decode=True)
        return payload.decode(errors='ignore') if payload else ''

    @staticmethod
    def _is_verify_email(text: str) -> bool:
        keywords = ['cordcloud', 'cordc', '验证码', 'verification', 'verify', '登录', 'login', '设备', 'device']
        s = text.lower()
        return any(k in s for k in keywords)

    @staticmethod
    def _extract_code(text: str) -> str:
        m = re.search(r'(?:验证码|code|verification code)[:：\s]*(\d{6})', text, re.I)
        if m:
            return m.group(1)
        m = re.search(r'\b(\d{6})\b', text)
        return m.group(1) if m else ''

    def _verify_device(self, token: str, code: str) -> dict:
        """
        完成陌生设备二步验证（一次性）
        POST /auth/login/2fa/verify 提交邮箱验证码，并携带 trust_device=1 永久信任当前设备指纹。
        验证成功后，相同 device_fingerprint 将不再触发验证。
        """
        if not code:
            return {
                'ret': 0,
                'msg': f'检测到陌生设备，需要进行二步验证。服务器已向 {self.email} 的邮箱发送验证码，'
                       f'请在 Action 输入的 device_code 中填入该验证码后重试（仅需一次），'
                       f'或配置 imap_password 自动读取。验证成功后，设备指纹将永不过期。'
            }

        verify_url = self.format_url('auth/login/2fa/verify')
        payload = {
            'token': token,
            'code': code,
            'method': 'email',
            'trust_device': '1'
        }
        response = self.session.post(
            verify_url,
            data=payload,
            headers={
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': self.format_url(f'auth/login/2fa?token={token}')
            },
            timeout=self.timeout,
            verify=False
        )
        try:
            result = response.json()
        except Exception:
            result = {'ret': 0, 'msg': f'设备验证提交失败，服务器返回：{response.text[:200]}'}
        log.info(f'设备验证接口返回结果：ret={result.get("ret")}, msg={result.get("msg", "")}')
        return result

    def _prepare_login(self) -> dict:
        """获取 CSRF Token、自动求解 Cap.js、构建登录表单数据"""
        login_url = self.format_url('auth/login')

        # 1. 获取登录页面 (获取 CSRF Token 和 Cap.js API 端点)
        login_page_res = self.session.get(login_url, timeout=self.timeout, verify=False)
        html_text = login_page_res.text

        # 2. 提取 CSRF Token
        token_match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_text)
        csrf_token = token_match.group(1) if token_match else ''

        # 3. 提取 Cap.js API 端点
        cap_api_match = re.search(r'data-cap-api-endpoint=["\']([^"\']+)["\']', html_text)
        cap_api_endpoint = cap_api_match.group(1) if cap_api_match else ''
        
        if cap_api_endpoint:
            log.info(f'提取到 Cap.js API 端点：{cap_api_endpoint}')
        else:
            log.warning('未能在登录页面找到 Cap.js API 端点')

        # 4. 尝试自动获取 Cap.js challenge 并求解
        cap_token = self.cap_token  # 优先使用配置中的 cap_token
        
        # 如果配置了 cap_token，给出警告（因为 cap_token 是一次性的）
        if cap_token:
            log.warning('配置文件中存在 cap_token，但 cap_token 是一次性的，可能已过期。建议清空配置文件中的 cap_token 让系统自动求解。')
        
        if not cap_token:
            try:
                # 使用 Playwright 自动求解获取 cap_token
                cap_token = solve_cap_challenge(login_url)
                
                if cap_token:
                    log.info('已自动求解 Cap.js 挑战获取 cap_token')
                else:
                    log.warning('Cap.js 自动求解失败，将尝试不带 cap_token 登录')
            except Exception as e:
                log.warning(f'获取 Cap.js challenge 失败：{e}，将尝试不带 cap_token 登录')

        # 5. 构建登录表单数据
        form_data = {
            'email': self.email,
            'passwd': self.passwd,
            'csrf_token': csrf_token,
            'device_fingerprint': self.device_fingerprint,
            'remember_me': 'week'
        }

        # 如果有 cap_token，添加它
        if cap_token:
            form_data['cap_token'] = cap_token

        # 如果有两步验证码，添加它
        if self.code:
            form_data['code'] = self.code

        return form_data

    def _post_login(self, form_data: dict) -> dict:
        response = self.session.post(
            self.format_url('auth/login'),
            data=form_data,
            timeout=self.timeout,
            verify=False
        )
        return response.json()

    def login(self) -> dict:
        # 1. 设置请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': self.format_url('auth/login')
        })

        # 2. 待验证设备：已有 token 时跳过登录直接验证
        #    关键：避免重新登录触发服务器重发验证码，导致已收到的验证码作废
        pending_token = self.device_token or self._load_token()
        if pending_token:
            log.info('检测到待验证的 device_token，直接提交验证码完成设备验证')
            code = self.device_code or self._auto_code()
            if code:
                return self._verify_pending(pending_token, code)
            log.warning('存在待验证的 device_token，但未获取到验证码，尝试重新登录')

        # 3. 正常登录
        log.info('开始正常登录流程')
        # 配置了 IMAP 时，先记录当前最新邮件 UID，之后只接受验证触发后新到的验证码邮件
        baseline_uid = self._latest_uid() if self.imap_password else -1
        result = self._post_login(self._prepare_login())

        # 4. 陌生设备验证 (ret == 2, need_device_2fa)
        if result.get('ret') == 2 and result.get('need_device_2fa'):
            token = result.get('token', '')
            log.warning('检测到陌生设备，需要进行二步验证，验证码已发送到邮箱')
            code = self.device_code or self._auto_code(min_uid=baseline_uid)
            if code:
                # 本次登录刚重发过验证码，用最新 token 验证，失败则保存 token 供下次直接验证
                log.info('已获取到验证码，提交设备验证')
                return self._verify_pending(token, code, reissued=True)
            # 未获取到验证码：保存 token，提示用户查收邮件后重试
            self._save_token(token)
            log.warning('未获取到验证码，已保存 token，请查收邮件后重试')
            return {
                'ret': 2,
                'msg': f'检测到陌生设备，验证码已发送至 {self.email} 的邮箱。'
                       f'请查收并将验证码填入 device_code 后重试（仅需一次），'
                       f'或配置 imap_password 自动读取。期间请勿再次运行，否则会重发验证码作废旧码。'
                       f'若运行环境无法保留 token，请同时将 device_token 设为：{token}'
            }

        return result

    def _verify_pending(self, token: str, code: str, reissued: bool = False) -> dict:
        verified = self._verify_device(token, code)
        if verified.get('ret') == 1:
            self._clear_token()
            log.info('设备验证成功，当前设备指纹已被信任，之后不再需要验证')
            return verified
        if reissued:
            self._save_token(token)
        verified = dict(verified)
        hint = ('本次登录已重新发送验证码，旧验证码已作废，'
                '请查收最新邮件并使用新验证码填入 device_code 后重试（请勿再次运行，避免再次重发验证码）'
                if reissued else
                '验证码无效或已过期，请确认输入的是最近一封邮件中的验证码，或删除 device_token 后重新运行')
        verified['msg'] = f"{verified.get('msg', '')}。{hint}"
        return verified

    def check_in(self) -> dict:
        check_in_url = self.format_url('user/checkin')
        return self.session.post(check_in_url, timeout=self.timeout, verify=False).json()

    def info(self) -> Tuple:
        user_url = self.format_url('user')
        html = self.session.get(user_url, timeout=self.timeout, verify=False).text
        today_used = re.search(
            '<span class="user-traffic-label">今日已用</span>.*?<span class="user-badge warning">(.*?)</span>',
            html, re.S)
        total_used = re.search(
            '<span class="user-traffic-label">过去已用</span>.*?<span class="user-badge primary">(.*?)</span>',
            html, re.S)
        rest = re.search(
            '<span class="user-traffic-label">剩余流量</span>.*?<span class="user-badge success" id="remain">(.*?)</span>',
            html, re.S)
        if today_used and total_used and rest:
            return today_used.group(1), total_used.group(1), rest.group(1)
        return ()

    def run(self):
        self.login()
        self.check_in()
        self.info()
