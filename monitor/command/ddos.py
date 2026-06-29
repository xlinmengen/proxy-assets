import time
import threading
from collections import defaultdict
from functools import wraps
from flask import request, jsonify

class DDoSProtector:
    """DDoS 基础防护类，支持白名单、自适应限流、并发限制、临时黑名单、全局防御模式。"""

    def __init__(self, rate_limit=100, concurrent_limit=10, block_time=300,
                 violation_factor=4.0, max_block_time=86400, suspicion_threshold=2,
                 release_factor=2.0, global_factor=100.0, global_max_factor=10.0,
                 overall_rate_limit=1.0):
        """
        :param rate_limit: 每个 IP 每分钟允许的最大请求数（基准值）
        :param concurrent_limit: 每个 IP 允许的最大并发连接数（基准值）
        :param block_time: 超过限制后封禁 IP 的秒数（基准值）
        :param violation_factor: 违规惩罚变化因子，范围 (0, 10]，映射到实际惩罚强度 (0, 2]
        :param max_block_time: 最大封禁时长（秒）
        :param suspicion_threshold: 恶意 Bot 触发封禁的嫌疑次数
        :param release_factor: 解封衰减因子，范围 (0, 10]，映射到实际保留比例 (0, 1]
        :param global_factor: 全局防御敏感度因子，值越小越敏感（防御强度随被封禁IP数量增长的速度）
        :param global_max_factor: 全局防御最大强度因子（封顶）
        :param overall_rate_limit: 整体访问速率控制，范围 (0, 1]，1 表示无限制，越小越慢
        """
        self.base_rate_limit = rate_limit
        self.concurrent_limit = concurrent_limit
        self.base_block_time = block_time

        # 违规因子映射 (0, 10] -> (0, 2]（曲线：平方映射）
        if violation_factor <= 0:
            violation_factor = 0.001
        self.violation_factor = self._map_curve(
            min(10.0, max(0.001, violation_factor)) / 5.0,
            power=1.5
        )

        self.max_block_time = max_block_time
        self.suspicion_threshold = suspicion_threshold

        # 解封衰减因子映射
        if release_factor <= 0:
            release_factor = 0.001
        raw_release = min(10.0, max(0.001, release_factor)) / 10.0
        self.release_decay_factor = self._map_curve(raw_release, power=0.5)

        # 整体速率控制
        self.overall_rate_limit = max(0.0, min(1.0, overall_rate_limit))
        self._overall_effective = self._map_curve(self.overall_rate_limit, power=1.5)

        # 全局防御参数
        self.global_factor = max(0.001, global_factor)
        self.global_max_factor = max(1.0, global_max_factor)

        # 存储结构
        self._ip_tokens = defaultdict(float)        # 上次刷新令牌的时间戳
        self._ip_available = defaultdict(float)     # 剩余令牌数（改用 float 避免精度截断）
        self._ip_concurrent = defaultdict(list)
        self._ip_blocked = {}
        self._ip_violation_count = defaultdict(int)
        self._ip_suspicion = defaultdict(int)
        self._ip_last_seen = defaultdict(float)
        self._ip_burst_over_limit = defaultdict(int) 

        self._lock = threading.RLock()
        self._whitelist = set()

    # ==================== 曲线映射函数 ====================
    def _map_curve(self, value: float, power: float = 1.5) -> float:
        if value <= 0:
            return 0
        if value >= 1:
            return 1
        return value ** power

    # ==================== 外置控制器 ====================
    def set_overall_rate_limit(self, rate: float):
        self.overall_rate_limit = max(0.0, min(1.0, rate))
        self._overall_effective = self._map_curve(self.overall_rate_limit, power=1.5)

    def get_overall_rate_limit(self) -> float:
        return self.overall_rate_limit

    def _apply_overall_rate_limit(self, base_limit: int) -> int:
        if self._overall_effective >= 1.0:
            return base_limit
        if self._overall_effective <= 0:
            return 0
        return max(1, int(base_limit * self._overall_effective))

    # ==================== 白名单管理 ====================
    def whitelist_add(self, ip: str):
        self._whitelist.add(ip)

    def whitelist_remove(self, ip: str):
        self._whitelist.discard(ip)

    def _is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist

    # ==================== 全局防御强度计算 ====================
    def _get_global_intensity_factor(self) -> float:
        blocked_count = len(self._ip_blocked)
        if blocked_count == 0:
            return 1.0
        ratio = blocked_count / self.global_factor
        factor = 1 + (ratio ** 1.5)
        return min(factor, self.global_max_factor)

    # ==================== 动态限流阈值 ====================
    def _get_effective_rate_limit(self, ip: str) -> int:
        if self._is_whitelisted(ip):
            return 999999

        global_factor_val = self._get_global_intensity_factor()
        violation_count = self._ip_violation_count.get(ip, 0)
        
        if violation_count == 0:
            personal_factor = 1.0
        else:
            personal_factor = 1 + self.violation_factor * (violation_count ** 0.8)

        total_factor = personal_factor * global_factor_val
        base_limit = int(self.base_rate_limit / total_factor)
        base_limit = max(5, base_limit)

        return self._apply_overall_rate_limit(base_limit)

    def _get_effective_concurrent_limit(self, ip: str) -> int:
        if self._is_whitelisted(ip):
            return 999999

        global_factor_val = self._get_global_intensity_factor()
        violation_count = self._ip_violation_count.get(ip, 0)
        
        if violation_count == 0:
            personal_factor = 1.0
        else:
            personal_factor = 1 + self.violation_factor * (violation_count ** 0.8)

        total_factor = personal_factor * global_factor_val
        base_limit = int(self.concurrent_limit / total_factor)
        base_limit = max(2, base_limit)

        return self._apply_overall_rate_limit(base_limit)

    # ==================== 嫌疑衰减 ====================
    def _decay_suspicion(self, ip: str):
        now = time.time()
        last_seen = self._ip_last_seen.get(ip, now)
        elapsed = now - last_seen

        if elapsed >= 600:
            decay_ratio = min(1.0, elapsed / 3600)
            old_suspicion = self._ip_suspicion.get(ip, 0)
            new_suspicion = max(0, int(old_suspicion * (1 - decay_ratio * 0.5)))
            if new_suspicion == 0:
                self._ip_suspicion.pop(ip, None)
            else:
                self._ip_suspicion[ip] = new_suspicion
            self._ip_last_seen[ip] = now

    # ==================== 黑名单管理 ====================
    def _is_blocked(self, ip: str) -> bool:
        if ip in self._ip_blocked:
            if time.time() < self._ip_blocked[ip]:
                return True
            with self._lock:
                # 异步或超时到期后安全移除
                self._ip_blocked.pop(ip, None)

                # 解封时衰减违规及爆发请求计数
                old_count = self._ip_violation_count.get(ip, 0)
                if old_count > 0:
                    new_count = max(1, int(old_count * self.release_decay_factor)) if self.release_decay_factor < 1 else max(0, old_count - 1)
                    self._ip_violation_count[ip] = new_count

                old_suspicion = self._ip_suspicion.get(ip, 0)
                if old_suspicion > 0:
                    new_suspicion = max(1, int(old_suspicion * self.release_decay_factor))
                    self._ip_suspicion[ip] = new_suspicion

                self._ip_burst_over_limit.pop(ip, None)
                self._ip_last_seen[ip] = time.time()
        return False

    def _block_ip(self, ip: str, violation: bool = False):
        with self._lock:
            if violation:
                self._ip_violation_count[ip] += 1
                violation_count = self._ip_violation_count[ip]
                growth_factor = 1 + self.violation_factor * (violation_count ** 1.2)
                dynamic_block_time = min(self.base_block_time * growth_factor, self.max_block_time)
            else:
                dynamic_block_time = self.base_block_time

            self._ip_blocked[ip] = time.time() + dynamic_block_time
            self._ip_tokens.pop(ip, None)
            self._ip_available.pop(ip, None)
            self._ip_concurrent.pop(ip, None)
            self._ip_burst_over_limit.pop(ip, None)

    # ==================== 攻击者指纹识别 ====================
    def _is_malicious_bot(self, ip: str, headers: dict) -> bool:
        ua = headers.get('User-Agent', '').lower()
        bad_patterns = [
            'curl', 'wget', 'python-requests', 'scrapy',
            'java', 'perl', 'ruby',
            'nikto', 'sqlmap', 'nmap', 'masscan'
        ]

        is_suspicious = any(pattern in ua for pattern in bad_patterns)

        with self._lock:
            self._ip_last_seen[ip] = time.time()
            self._decay_suspicion(ip)

            if is_suspicious:
                self._ip_suspicion[ip] = self._ip_suspicion.get(ip, 0) + 1
                if self._ip_suspicion[ip] >= self.suspicion_threshold:
                    return True
            return False

    # ==================== 令牌桶限流 ====================
    def _check_rate_limit(self, ip: str, headers: dict) -> bool:
        with self._lock:
            now = time.time()
            effective_limit = self._get_effective_rate_limit(ip)

            if effective_limit <= 0:
                return False

            if self._is_malicious_bot(ip, headers):
                self._block_ip(ip, violation=True)
                return False

            last_check = self._ip_tokens.get(ip, 0)
            if last_check == 0:
                self._ip_tokens[ip] = now
                self._ip_available[ip] = float(effective_limit)
                last_check = now

            elapsed = now - last_check
            # 令牌恢复速率（每秒恢复多少个令牌）
            token_recovery_rate = effective_limit / 60.0
            new_tokens = elapsed * token_recovery_rate

            if new_tokens > 0:
                self._ip_available[ip] = min(float(effective_limit), self._ip_available[ip] + new_tokens)
                # 重点优化：只步进消耗掉的时间，避免微小时间差碎片在高并发下被持续刷零
                self._ip_tokens[ip] = now

            # 判断是否有足够令牌供给本次请求
            if  self._ip_available[ip] >= 1.0:
                self._ip_available[ip] -= 1.0
                # 如果请求正常，逐渐消减超限作案计数
                if ip in self._ip_burst_over_limit and self._ip_burst_over_limit[ip] > 0:
                    self._ip_burst_over_limit[ip] -= 1
                return True
            else:
                # 重点优化：令牌耗尽时，默认只予以拦截（返回限流），绝非直接Ban。
                # 只有当用户触发限流后，继续不要命地发起高频冲击（顶风作案超过有效阈值），才判定为恶意攻击并Ban。
                self._ip_burst_over_limit[ip] += 1
                if self._ip_burst_over_limit[ip] > max(15, int(effective_limit * 0.3)):
                    self._block_ip(ip, violation=True)
                return False

    # ==================== 并发限制 ====================
    def _increase_concurrent(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            effective_limit = self._get_effective_concurrent_limit(ip)

            if effective_limit <= 0:
                return False

            active = [t for t in self._ip_concurrent[ip] if now - t < 30]
            
            if len(active) >= effective_limit:
                self._ip_concurrent[ip] = active
                return False
                
            active.append(now)
            self._ip_concurrent[ip] = active
            return True

    def _decrease_concurrent(self, ip: str):
        with self._lock:
            if self._ip_concurrent[ip]:
                self._ip_concurrent[ip].pop(0)

    # ==================== 统计接口 ====================
    def get_stats(self) -> dict:
        return {
            'blocked_ips': len(self._ip_blocked),
            'active_ips': len(self._ip_tokens),
            'global_defense_factor': self._get_global_intensity_factor(),
            'whitelist_size': len(self._whitelist),
            'overall_rate_limit': self.overall_rate_limit,
            'overall_effective': self._overall_effective
        }

    # ==================== 对外装饰器 ====================
    def protect(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr

            if self._is_whitelisted(ip):
                return f(*args, **kwargs)

            if self._is_blocked(ip):
                return jsonify({'error': 'Too many requests, temporarily banned'}), 429

            if not self._check_rate_limit(ip, request.headers):
                # 优化：区分是被拉黑了还是仅仅被限流
                if self._is_blocked(ip):
                    return jsonify({'error': 'Too many requests, temporarily banned'}), 429
                return jsonify({'error': 'Rate limit exceeded'}), 429

            if not self._increase_concurrent(ip):
                return jsonify({'error': 'Too many concurrent connections'}), 429

            try:
                return f(*args, **kwargs)
            finally:
                self._decrease_concurrent(ip)

        return decorated
    
    def is_blocked(self, ip: str) -> bool: return self._is_blocked(ip)
    def is_whitelisted(self, ip: str) -> bool: return self._is_whitelisted(ip)
    def increase_concurrent(self, ip: str) -> bool: return self._increase_concurrent(ip)
    def decrease_concurrent(self, ip: str) -> None: return self._decrease_concurrent(ip)
    def check_rate_limit(self, ip: str, headers: dict) -> bool: return self._check_rate_limit(ip, headers)