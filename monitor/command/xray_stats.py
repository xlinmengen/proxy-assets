import time
import grpc
import copy
import logging
import datetime
import threading
from command_pb2.stats      import SysStatsRequest
from command_pb2.stats      import QueryStatsRequest
from command_pb2.stats_grpc import StatsServiceStub

# 配置日志
logger = logging.getLogger(__name__)

class XrayStats:
    """Xray 统计数据获取（原生 gRPC 实现）+ 实时流量监控"""

    def __init__(self, api_addr: str = "127.0.0.1:15", timeout: int = 5):
        """
        初始化 Xray gRPC 客户端
        :param api_addr: Xray API 地址，格式 "host:port"
        :param timeout: 默认超时时间（秒）
        """
        self.last_reset_date = None
        self.api_addr = api_addr
        self.timeout = timeout
        self.channel = None
        self.stub = None
        self._connect()
        
        # ========== 实时流量监控相关 ==========
        self._snapshot    = {}        # 上一秒的快照 {email: {"uplink": x, "downlink": y}}
        self._accumulated = {}        # 累计流量 {email: {"uplink": x, "downlink": y}}
        self._speed   = {}            # 实时速度 {email: {"uplink": x, "downlink": y}}
        self._running = False
        self._thread  = None
        
        # 启动监控线程
        self._start_monitor()
    
    def _connect(self):
        """建立 gRPC 连接"""
        try:
            self.channel = grpc.insecure_channel(
                self.api_addr,
                options=[
                    ('grpc.max_receive_message_length', 50 * 1024 * 1024),  # 50MB
                    ('grpc.keepalive_time_ms', 30000),      # 30秒心跳
                    ('grpc.keepalive_timeout_ms', 10000),   # 10秒超时
                    ('grpc.http2.max_pings_without_data', 0),
                    ('grpc.http2.min_time_between_pings_ms', 10000),
                    ('grpc.http2.max_ping_strikes', 0),     # 避免 ping 过多被关闭
                ]
            )
            self.stub = StatsServiceStub(self.channel)
            logger.info(f"Xray gRPC 连接成功: {self.api_addr}")
        except Exception as e:
            logger.error(f"Xray gRPC 连接失败: {e}")
    
    # ========== 监控线程相关方法 ==========
    def _start_monitor(self):
        """启动监控线程"""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("实时流量监控线程已启动")
    
    def _stop_monitor(self):
        """停止监控线程"""
        self._running = False
        if  self._thread:
            self._thread.join(timeout=2)
            logger.info("实时流量监控线程已停止")
    
    def check_monthly_reset(self):
        """检查是否需要重置月度流量"""
        today = datetime.date.today()
        
        if today.day == 1:
            if  self.last_reset_date is None or self.last_reset_date.month != today.month:
                self.last_reset_date = today
                return True
        return  False
    
    def _monitor_loop(self):
        """监控主循环（每秒执行）"""
        while self._running:
            try:
                current = self._query_all_traffic_raw()
                
                speed = {}
                accumulated = {}
                for email, curr_data in current.items():
                    last = self._snapshot.get(email, {"uplink": 0, "downlink": 0})
                    
                    # 计算差值（确保不为负数）
                    up_delta   = max(0, curr_data["uplink"]   - last["uplink"])
                    down_delta = max(0, curr_data["downlink"] - last["downlink"])
                    
                    # 更新速度
                    speed[email] = {
                        "uplink"  : up_delta,
                        "downlink": down_delta
                    }

                    # 累加到累计流量
                    acc_uplink   = self._accumulated.get(email, {}).get("uplink"  , 0)
                    acc_downlink = self._accumulated.get(email, {}).get("downlink", 0)
                    accumulated[email] = {
                        "uplink"  : acc_uplink   + up_delta,
                        "downlink": acc_downlink + down_delta
                    }
                
                self._speed = speed
                self._snapshot = current
                self._accumulated = accumulated if self.check_monthly_reset() else (self._accumulated | accumulated)

            except Exception as e:
                logger.error(f"监控循环执行失败: {e}")
            
            time.sleep(1)
    
    def _query_all_traffic_raw(self) -> dict[str, dict]:
        """
        查询所有实时流量（原始数据，不涉及累计）
        返回格式：{email: {"uplink": x, "downlink": y}}
        """
        result = self._query_traffic("", reset=False)
        traffic_dict = {}
        
        for stat in result.get('stats', []):
            name  = stat['name']
            value = stat['value']
            
            if name.startswith('user>>>') and '>>>traffic>>>' in name:
                parts = name.split('>>>')
                if len(parts) >= 4 and parts[0] == 'user' and parts[2] == 'traffic':
                    email = parts[1]
                    direction = parts[3]
                    
                    if email not in traffic_dict:
                        traffic_dict[email] = {'uplink': 0, 'downlink': 0}
                    
                    if direction == 'uplink':
                        traffic_dict[email]['uplink'] = value
                    if direction == 'downlink':
                        traffic_dict[email]['downlink'] = value
        return copy.deepcopy(traffic_dict)
    
    # ========== 对外接口（供 API 调用） ==========
    def get_user_traffic(self, email: str) -> dict:
        """
        获取指定用户的累计流量和实时速度
        返回格式：
        {
            'accumulated': {'uplink': 123, 'downlink': 456},
            'speed': {'uplink': 12, 'downlink': 34}
        }
        """
        accumulated = self._accumulated.get(email, {"uplink": 0, "downlink": 0})
        speed = self._speed.get(email, {"uplink": 0, "downlink": 0})
        
        return copy.deepcopy({
            'accumulated': accumulated,
            'speed': speed
        })
    
    def get_all_users_traffic(self) -> dict[str, dict]:
        """
        获取所有用户的累计流量和实时速度
        返回格式：
        {
            'user@example.com': {
                'accumulated': {'uplink': 123, 'downlink': 456},
                'speed': {'uplink': 12, 'downlink': 34}
            },
            ...
        }
        """
        result = {}
        all_emails = set(self._accumulated.keys()) | set(self._speed.keys())
        for email in all_emails:
            result[email] = {
                'accumulated': self._accumulated.get(email, {"uplink": 0, "downlink": 0}),
                'speed': self._speed.get(email, {"uplink": 0, "downlink": 0})
            }
        
        return copy.deepcopy(result)
    
    def get_system_stats(self) -> dict:
        """
        获取系统统计信息
        """
        try:
            request  = SysStatsRequest()
            response = self.stub.GetSysStats(request, timeout=self.timeout)

            # 获取各字段值（带默认值）
            uptime = getattr(response, 'Uptime', 0)
            alloc  = getattr(response, 'Alloc' , 0)

            return {
                'uptime': uptime,
                'memory': alloc,
                'NumGoroutine': getattr(response, 'NumGoroutine', 0),
                'NumGC': getattr(response, 'NumGC', 0),
                'Alloc': alloc,
                'TotalAlloc': getattr(response, 'TotalAlloc', 0),
                'Sys': getattr(response, 'Sys', 0),
                'Mallocs': getattr(response, 'Mallocs', 0),
                'Frees': getattr(response, 'Frees', 0),
                'LiveObjects': getattr(response, 'LiveObjects', 0),
                'PauseTotalNs': getattr(response, 'PauseTotalNs', 0),
                'Uptime': uptime,
            }
        except Exception as e:
            logger.error(f"获取系统统计失败: {e}")
            return {
                'uptime': 0,
                'memory': 0,
                'error': str(e)
            }
    
    def _query_traffic(self, pattern: str, reset: bool) -> dict:
        """
        通用流量查询方法
        返回包含 'stats' 列表的字典，或包含 'error' 的字典
        """
        try:
            request = QueryStatsRequest(
                pattern=pattern,
                reset=reset
            )
            response = self.stub.QueryStats(request, timeout=self.timeout)

            stats = []
            for i, stat in enumerate(response.stat):
                stats.append({
                    'name' : stat.name,
                    'value': stat.value
                })

            return copy.deepcopy({'stats': stats})
        except Exception as e: return {'error': str(e)}

    def close(self):
        """关闭 gRPC 连接"""
        self._stop_monitor()
        if  self.channel:
            self.channel.close()
            logger.info("Xray gRPC 连接已关闭")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()