from server import Server
from utilities import format_res

class AccountHandler():
  """This handles anything to do with travellers and their accounts"""

  server: Server

  def __init__(self, server: Server):
    self.server = server

    @server.register
    async def total_travellers(wss, event, ref):
      """Get the total number of travellers"""
      # TODO: Return total travellers
      return format_res('totalTravellers', ref, totalTravellers=0)

    @server.register
    async def fetch_travellers(wss, event, ref):
      """List all traveller ids"""
      # TODO: Return traveller ids
      return format_res('fetchTravellers', ref, travellerIds=[])
