from flask import Flask, request, jsonify
import random
import string
import json
import time
import requests
import uuid
import pyotp

app = Flask(__name__)

class FacebookLogin:
    def __init__(self, uid_phone_mail="", password="", twwwoo2fa="", user_agent=""):
        self.uid_phone_mail = uid_phone_mail
        self.password = password
        self.twwwoo2fa = twwwoo2fa
        self.user_agent = user_agent
        self.url = "https://b-graph.facebook.com/auth/login"
        self.headers = {
            "content-type": "application/x-www-form-urlencoded",
            "x-fb-request-analytics-tags": '{"network_tags":{"product":"350685531728","retry_attempt":"0"},"application_tags":"unknown"}',
            "x-fb-net-hni": "45201", 
            "zero-rated": "0",
            "x-fb-sim-hni": "45201",
            "x-fb-connection-quality": "EXCELLENT",
            "x-fb-friendly-name": "authenticate",
            "x-fb-connection-bandwidth": "78032897",
            "x-tigon-is-retry": "False",
            "user-agent": self.user_agent,
            "authorization": "OAuth null",
            "x-fb-connection-type": "WIFI",
            "x-fb-device-group": "3342",
            "priority": "u=3,i",
            "x-fb-http-engine": "Liger",
            "x-fb-client-ip": "True",
            "x-fb-server-cluster": "True"
        }
        self.data = {
            "adid": "a63f3e1b-4446-40dd-be8f-9a01e5207062",
            "format": "json",
            "device_id": "a22b194a-84c4-4dcf-8e8e-ecc05ae474ad", 
            "email": self.uid_phone_mail,
            "password": self.password,
            "generate_analytics_claim": "1",
            "community_id": "",
            "linked_guest_account_userid": "",
            "cpl": "true",
            "try_num": "1",
            "family_device_id": "a22b194a-84c4-4dcf-8e8e-ecc05ae474ad",
            "secure_family_device_id": "95ea3bfe-07d8-4863-a520-4dbe79704e04",
            "sim_serials": '["89014103211118510720"]',
            "credentials_type": "password",
            "openid_flow": "android_login",
            "openid_provider": "google",
            "openid_tokens": "[]",
            "account_switcher_uids": '["'+self.uid_phone_mail+'"]',
            "fb4a_shared_phone_cpl_experiment": "fb4a_shared_phone_nonce_cpl_at_risk_v3",
            "fb4a_shared_phone_cpl_group": "enable_v3_at_risk",
            "enroll_misauth": "false",
            "generate_session_cookies": "1",
            "error_detail_type": "button_with_disabled",
            "source": "login",
            "machine_id": "EvuAZ37kNVMnKcUo51EIB9uP",
            "jazoest": "22610",
            "meta_inf_fbmeta": "V2_UNTAGGED", 
            "advertiser_id": "a63f3e1b-4446-40dd-be8f-9a01e5207062",
            "encrypted_msisdn": "",
            "currently_logged_in_userid": "0",
            "locale": "vi_VN",
            "client_country_code": "VN",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "Fb4aAuthHandler",
            "api_key": "882a8490361da98702bf97a021ddc14d",
            "sig": "214049b9f17c38bd767de53752b53946",
            "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
        }
        self.session = requests.Session()

    def _parse_proxy_for_token_check(self, proxy: str):
        """Hàm helper để parse proxy cho việc kiểm tra token"""
        try:
            if not proxy or proxy.strip() == "":
                return None
                
            proxy = proxy.strip()
            
            # Handle ip:port:user:pass format
            if proxy.count(':') == 3 and '://' not in proxy:
                parts = proxy.split(':')
                if len(parts) == 4:
                    ip, port, user, password = parts
                    proxy_url = f"http://{user}:{password}@{ip}:{port}"
                    return {
                        "http": proxy_url,
                        "https": proxy_url
                    }
            
            # Handle ip:port format
            elif proxy.count(':') == 1 and '://' not in proxy:
                proxy_url = f"http://{proxy}"
                return {
                    "http": proxy_url,
                    "https": proxy_url
                }
            
            # Handle full URL format
            elif "://" in proxy:
                return {
                    "http": proxy,
                    "https": proxy
                }
            else:
                return None
                
        except Exception as e:
            return None

    def check_facebook_token(self, token, user_agent=None, proxy=None):
        """
        Kiểm tra token Facebook chỉ dùng 1 API: graph.facebook.com/me
        Args: 
            token - Access token Facebook
            user_agent - User-Agent thiết bị (phải khớp với thiết bị login)
            proxy - Máy chủ proxy (phải khớp với proxy login)
        Returns: {"status": "live"|"die"|"error", ...}
        """
        try:
            # CRITICAL: Use same User Agent as login device to avoid detection
            headers = {
                "User-Agent": user_agent or "Dalvik/2.1.0 (Linux; U; Android 11; SM-G973F Build/RP1A.200720.012) [FBAN/FB4A;FBAV/385.0.0.23.104;]"
            }
            
            # CRITICAL: Use same proxy as login to avoid detection
            check_session = requests.Session()
            if proxy:
                proxy_config = self._parse_proxy_for_token_check(proxy)
                if proxy_config:
                    check_session.proxies = proxy_config
            
            # Chỉ sử dụng 1 API duy nhất
            response = check_session.get(
                f"https://graph.facebook.com/me?access_token={token}",
                headers=headers,
                timeout=15
            )
            
            # Parse response
            try:
                data = response.json()
            except json.JSONDecodeError:
                return {"status": "die", "error": "Invalid JSON"}
            
            # Check result
            if response.status_code == 200 and 'id' in data:
                return {
                    "status": "live",
                    "user_id": data.get('id'),
                    "name": data.get('name'),
                    "email": data.get('email'),
                    "data": data
                }
            else:
                error = data.get('error', {})
                error_msg = error.get('message', 'Token invalid')
                return {
                    "status": "die", 
                    "error": error_msg,
                    "code": error.get('code')
                }
                
        except Exception as e:
            return {"status": "error", "error": str(e)}
        
        finally:
            # Close session
            try:
                check_session.close()
            except:
                pass

    def set_proxy(self, proxy_str):
        """Thiết lập proxy theo định dạng ip:port:user:pass"""
        if not proxy_str:
            return False
        
        try:
            parts = proxy_str.split(':')
            if len(parts) != 4:
                return False
            
            ip, port, user, password = parts
            proxy_url = f"http://{user}:{password}@{ip}:{port}"
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            return True
        except:
            return False
        
    def login(self):
        """Thực hiện login và trả về kết quả JSON"""
        result = {
            "status": "error",
            "uid": None,
            "message": "",
            "cookie": None,
            "token": None
        }
        
        try:
            # Request đầu tiên
            response = self.session.post(self.url, headers=self.headers, data=self.data)
            response_json = response.json()
            
            # Kiểm tra nếu cần 2FA
            if 'error' in response_json and 'error_data' in response_json['error']:
                if not self.twwwoo2fa:
                    result["message"] = "Cần mã 2FA nhưng không được cung cấp"
                    return result
                
                # Tạo mã 2FA và gửi request thứ 2
                twofactor_code = pyotp.TOTP(self.twwwoo2fa).now()
                response_2 = self.session.post('https://b-graph.facebook.com/auth/login', data={
                    'locale': 'vi_VN',
                    'format': 'json',
                    'email': self.uid_phone_mail,
                    'device_id': str(uuid.uuid4()),
                    'access_token': "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                    'generate_session_cookies': 'true',
                    'generate_machine_id': '1',
                    'twofactor_code': twofactor_code,
                    'credentials_type': 'two_factor',
                    'error_detail_type': 'button_with_disabled',
                    'first_factor': response_json['error']['error_data']['login_first_factor'],
                    'password': self.password,
                    'userid': response_json['error']['error_data']['uid'],
                    'machine_id': response_json['error']['error_data']['login_first_factor']
                }, headers=self.headers)
                
                response_2_json = response_2.json()
                
                # Kiểm tra login thành công
                if 'access_token' in response_2_json:
                    # Kiểm tra token trước khi trả về thành công
                    proxy_string = None
                    if hasattr(self.session, 'proxies') and self.session.proxies:
                        # Lấy proxy string từ session
                        proxy_url = self.session.proxies.get('http', '')
                        if '@' in proxy_url:
                            # Extract từ format http://user:pass@ip:port
                            proxy_part = proxy_url.split('@')[1]  # ip:port
                            auth_part = proxy_url.split('//')[1].split('@')[0]  # user:pass
                            proxy_string = f"{proxy_part}:{auth_part}".replace(':', ':')
                            # Reformat to ip:port:user:pass
                            parts = proxy_url.replace('http://', '').split('@')
                            if len(parts) == 2:
                                user_pass = parts[0]
                                ip_port = parts[1]
                                if ':' in user_pass and ':' in ip_port:
                                    user, password = user_pass.split(':', 1)
                                    ip, port = ip_port.split(':', 1)
                                    proxy_string = f"{ip}:{port}:{user}:{password}"
                    
                    token_check = self.check_facebook_token(
                        response_2_json['access_token'], 
                        self.user_agent, 
                        proxy_string
                    )
                    
                    if token_check["status"] == "live":
                        result["status"] = "success"
                        result["uid"] = response_json['error']['error_data']['uid']
                        result["message"] = "Đăng nhập thành công"
                        result["token"] = response_2_json['access_token']
                        
                        # Lấy cookies nếu có
                        if 'session_cookies' in response_2_json:
                            cookies_string = ""
                            for cookie in response_2_json['session_cookies']:
                                cookies_string += f"{cookie['name']}={cookie['value']}; "
                            result["cookie"] = cookies_string.rstrip('; ')
                    else:
                        result["message"] = f"Token không hợp lệ: {token_check.get('error', 'Token die')}"
                else:
                    result["message"] = "Đăng nhập thất bại: " + str(response_2_json.get('error', {}).get('message', 'Lỗi không xác định'))
            else:
                # Kiểm tra nếu login thành công ngay lần đầu
                if 'access_token' in response_json:
                    # Kiểm tra token trước khi trả về thành công
                    proxy_string = None
                    if hasattr(self.session, 'proxies') and self.session.proxies:
                        # Lấy proxy string từ session
                        proxy_url = self.session.proxies.get('http', '')
                        if '@' in proxy_url:
                            # Extract từ format http://user:pass@ip:port
                            parts = proxy_url.replace('http://', '').split('@')
                            if len(parts) == 2:
                                user_pass = parts[0]
                                ip_port = parts[1]
                                if ':' in user_pass and ':' in ip_port:
                                    user, password = user_pass.split(':', 1)
                                    ip, port = ip_port.split(':', 1)
                                    proxy_string = f"{ip}:{port}:{user}:{password}"
                    
                    token_check = self.check_facebook_token(
                        response_json['access_token'], 
                        self.user_agent, 
                        proxy_string
                    )
                    
                    if token_check["status"] == "live":
                        result["status"] = "success"
                        result["uid"] = self.uid_phone_mail
                        result["message"] = "Đăng nhập thành công (không cần 2FA)"
                        result["token"] = response_json['access_token']
                        
                        if 'session_cookies' in response_json:
                            cookies_string = ""
                            for cookie in response_json['session_cookies']:
                                cookies_string += f"{cookie['name']}={cookie['value']}; "
                            result["cookie"] = cookies_string.rstrip('; ')
                    else:
                        result["message"] = f"Token không hợp lệ: {token_check.get('error', 'Token die')}"
                else:
                    result["message"] = "Đăng nhập thất bại: " + str(response_json.get('error', {}).get('message', 'Lỗi không xác định'))
                    
        except requests.RequestException as e:
            result["message"] = f"Lỗi kết nối: {str(e)}"
        except json.JSONDecodeError as e:
            result["message"] = f"Lỗi parse JSON: {str(e)}"
        except Exception as e:
            result["message"] = f"Lỗi không xác định: {str(e)}"
            
        return result

@app.route('/login', methods=['POST'])
def facebook_login():
    """API endpoint để đăng nhập Facebook"""
    try:
        # Lấy dữ liệu từ request
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "Không có dữ liệu JSON trong request"
            }), 400
        
        # Kiểm tra các trường bắt buộc
        required_fields = ['uid_phone_mail', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    "status": "error",
                    "message": f"Trường '{field}' là bắt buộc"
                }), 400
        
        # Lấy thông tin từ request
        uid_phone_mail = data['uid_phone_mail']
        password = data['password']
        twwwoo2fa = data.get('twwwoo2fa', '').replace(' ', '')
        user_agent = data.get('user_agent', 'Dalvik/2.1.0 (Linux; U; Android 11; M2101K6I Build/RKQ1.200826.002) [FBAN/FB4A;FBAV/437.0.0.42.121;FBPN/com.facebook.katana;FBLC/vi_VN;FBBV/517321098;FBCR/Gmobile;FBMF/Xiaomi;FBBD/Redmi;FBDV/M2101K6I;FBSV/11;FBCA/arm64-v8a:armeabi-v7a;FBDM/{density=2.75,width=1080,height=2400};FB_FW/1;FBRV/0;]')
        proxy = data.get('proxy', '')
        
        # Tạo instance FacebookLogin
        fb_login = FacebookLogin(uid_phone_mail, password, twwwoo2fa, user_agent)
        
        # Thiết lập proxy nếu có
        if proxy:
            proxy_set = fb_login.set_proxy(proxy)
            if not proxy_set:
                return jsonify({
                    "status": "error",
                    "message": "Định dạng proxy không hợp lệ. Sử dụng format: ip:port:user:pass"
                }), 400
        
        # Thực hiện login
        result = fb_login.login()
        
        # Trả về kết quả
        status_code = 200 if result["status"] == "success" else 400
        return jsonify(result), status_code
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Lỗi server: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "success",
        "message": "Facebook Login API đang hoạt động"
    })

@app.route('/', methods=['GET'])
def home():
    """Trang chủ với hướng dẫn sử dụng"""
    return jsonify({
        "message": "Facebook Login API",
        "endpoints": {
            "POST /login": {
                "description": "Đăng nhập Facebook",
                "parameters": {
                    "uid_phone_mail": "Email/Phone/UID (bắt buộc)",
                    "password": "Mật khẩu (bắt buộc)",
                    "twwwoo2fa": "Mã 2FA (tùy chọn)",
                    "user_agent": "User Agent (tùy chọn)",
                    "proxy": "Proxy format ip:port:user:pass (tùy chọn)"
                },
                "example": {
                    "uid_phone_mail": "example@email.com",
                    "password": "yourpassword",
                    "twwwoo2fa": "ABCD1234EFGH5678",
                    "user_agent": "Mozilla/5.0...",
                    "proxy": "1.2.3.4:8080:user:pass"
                }
            },
            "GET /health": "Kiểm tra trạng thái API"
        }
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)