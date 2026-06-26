import grpc
from . import stats

class StatsServiceStub(object):
  def __init__(self, channel):
    self.GetStats = channel.unary_unary(
        '/xray.app.stats.command.StatsService/GetStats',
        request_serializer=stats.GetStatsRequest.SerializeToString,
        response_deserializer=stats.GetStatsResponse.FromString,
        _registered_method=True)
    self.GetStatsOnline = channel.unary_unary(
        '/xray.app.stats.command.StatsService/GetStatsOnline',
        request_serializer=stats.GetStatsRequest.SerializeToString,
        response_deserializer=stats.GetStatsResponse.FromString,
        _registered_method=True)
    self.QueryStats = channel.unary_unary(
        '/xray.app.stats.command.StatsService/QueryStats',
        request_serializer=stats.QueryStatsRequest.SerializeToString,
        response_deserializer=stats.QueryStatsResponse.FromString,
        _registered_method=True)
    self.GetSysStats = channel.unary_unary(
        '/xray.app.stats.command.StatsService/GetSysStats',
        request_serializer=stats.SysStatsRequest.SerializeToString,
        response_deserializer=stats.SysStatsResponse.FromString,
        _registered_method=True)
    self.GetStatsOnlineIpList = channel.unary_unary(
        '/xray.app.stats.command.StatsService/GetStatsOnlineIpList',
        request_serializer=stats.GetStatsRequest.SerializeToString,
        response_deserializer=stats.GetStatsOnlineIpListResponse.FromString,
        _registered_method=True)
    self.GetAllOnlineUsers = channel.unary_unary(
        '/xray.app.stats.command.StatsService/GetAllOnlineUsers',
        request_serializer=stats.GetAllOnlineUsersRequest.SerializeToString,
        response_deserializer=stats.GetAllOnlineUsersResponse.FromString,
        _registered_method=True)

class StatsServiceServicer(object):
  def GetStats(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetStatsOnline(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def QueryStats(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetSysStats(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetStatsOnlineIpList(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetAllOnlineUsers(self, request, context):
    """Missing associated documentation comment in .proto file."""
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

def add_StatsServiceServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'GetStats': grpc.unary_unary_rpc_method_handler(
          servicer.GetStats,
          request_deserializer=stats.GetStatsRequest.FromString,
          response_serializer=stats.GetStatsResponse.SerializeToString,
      ),
      'GetStatsOnline': grpc.unary_unary_rpc_method_handler(
          servicer.GetStatsOnline,
          request_deserializer=stats.GetStatsRequest.FromString,
          response_serializer=stats.GetStatsResponse.SerializeToString,
      ),
      'QueryStats': grpc.unary_unary_rpc_method_handler(
          servicer.QueryStats,
          request_deserializer=stats.QueryStatsRequest.FromString,
          response_serializer=stats.QueryStatsResponse.SerializeToString,
      ),
      'GetSysStats': grpc.unary_unary_rpc_method_handler(
          servicer.GetSysStats,
          request_deserializer=stats.SysStatsRequest.FromString,
          response_serializer=stats.SysStatsResponse.SerializeToString,
      ),
      'GetStatsOnlineIpList': grpc.unary_unary_rpc_method_handler(
          servicer.GetStatsOnlineIpList,
          request_deserializer=stats.GetStatsRequest.FromString,
          response_serializer=stats.GetStatsOnlineIpListResponse.SerializeToString,
      ),
      'GetAllOnlineUsers': grpc.unary_unary_rpc_method_handler(
          servicer.GetAllOnlineUsers,
          request_deserializer=stats.GetAllOnlineUsersRequest.FromString,
          response_serializer=stats.GetAllOnlineUsersResponse.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'xray.app.stats.command.StatsService', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
  server.add_registered_method_handlers('xray.app.stats.command.StatsService', rpc_method_handlers)

class StatsService(object):
  @staticmethod
  def GetStats(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/GetStats',
      stats.GetStatsRequest.SerializeToString,
      stats.GetStatsResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)

  @staticmethod
  def GetStatsOnline(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/GetStatsOnline',
      stats.GetStatsRequest.SerializeToString,
      stats.GetStatsResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)

  @staticmethod
  def QueryStats(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/QueryStats',
      stats.QueryStatsRequest.SerializeToString,
      stats.QueryStatsResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)

  @staticmethod
  def GetSysStats(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/GetSysStats',
      stats.SysStatsRequest.SerializeToString,
      stats.SysStatsResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)

  @staticmethod
  def GetStatsOnlineIpList(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/GetStatsOnlineIpList',
      stats.GetStatsRequest.SerializeToString,
      stats.GetStatsOnlineIpListResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)

  @staticmethod
  def GetAllOnlineUsers(request,
      target,
      options=(),
      channel_credentials=None,
      call_credentials=None,
      insecure=False,
      compression=None,
      wait_for_ready=None,
      timeout=None,
      metadata=None):
    return grpc.experimental.unary_unary(
      request,
      target,
      '/xray.app.stats.command.StatsService/GetAllOnlineUsers',
      stats.GetAllOnlineUsersRequest.SerializeToString,
      stats.GetAllOnlineUsersResponse.FromString,
      options,
      channel_credentials,
      insecure,
      call_credentials,
      compression,
      wait_for_ready,
      timeout,
      metadata,
      _registered_method=True)