import smtplib
from email.message import EmailMessage

# SMTP 服务器映射
SMTP_MAP = {
    'gmail.com': ('smtp.gmail.com', 587),      # 需要应用专用密码
    'qq.com': ('smtp.qq.com', 587),            # 需要授权码
    '163.com': ('smtp.163.com', 465),          # 需要授权码
    '126.com': ('smtp.126.com', 465),
    'outlook.com': ('smtp.office365.com', 587),
    'hotmail.com': ('smtp.office365.com', 587),
    'aliyun.com' : ('smtp.aliyun.com', 465),
    'foxmail.com': ('smtp.qq.com', 587),
}

class EmailSMTP:
    domain : str
    account: tuple[str, str]
    def __init__(self, email:str, passcode:str):
        self.set_email(email, passcode)
    def set_email(self, email:str, passcode:str):
        self.account = (email, passcode)
        self.domain  =  email.split('@')[-1].lower()
    def send_email(self, to_email:str, message:list|tuple, use_html:bool = False, from_name:str = '{}'):
        if self.domain not in SMTP_MAP: return False
        
        smtp_host, smtp_port = SMTP_MAP[self.domain]
        
        msg = EmailMessage()
        msg['From'] = from_name.replace('{}', self.account[0]) or self.account[0]
        msg['To'] = to_email
        msg['Subject'] = message[0]
        
        if  use_html:
            msg.add_alternative(message[1], subtype='html')
        else:
            msg.set_content(message[1])
        
        try:
            if  smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
                    server.login(*self.account)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                    server.starttls()
                    server.login(*self.account)
                    server.send_message(msg)
        except: return False
        else  : return True