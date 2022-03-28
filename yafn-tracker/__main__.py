import time
import socket
import asyncio
import ipaddress

import cbor2
from aiohttp import web
from Crypto.Hash import SHA256, RIPEMD160
from Crypto.PublicKey import RSA

def ripemd160(data):
  hash = RIPEMD160.new()
  hash.update(data)

  return hash.digest()

def sha256(data):
  hash = SHA256.new()
  hash.update(data)

  return hash.digest()

def generate_uid(pubkey):
  pubkey = RSA.import_key(pubkey)
  pubkey = pubkey.public_key()

  n = pubkey.n.to_bytes(128, 'big')
  e = pubkey.e.to_bytes(3, 'big')

  return ripemd160(sha256(n + e))

async def _readall(reader, size):
  buffer = b''

  while len(buffer) < size:
    buffer += await reader.read(size - len(buffer))

  return buffer

class Peer:
  def __init__(self, addr):
    self.addr = addr
    self.uid = None
    self.last_check = 0
    self.failed_checks = 0
    self.works = False
    self.latency = 0

  async def check(self):
    self.last_check = time.time()

    try:
      addr = socket.gethostbyname(self.addr)
      addr = ipaddress.ip_address(addr)
      if not addr.is_global:
        raise Exception

      reader, writer = await asyncio.wait_for(
        asyncio.open_connection(str(addr), 49871),
        timeout=5
      )

      data = await asyncio.wait_for(
        _readall(reader, 172),
        timeout=5
      )

      if len(data) != 172:
        raise Exception

      if data[:10] != b'YAFN HELLO':
        raise Exception

      self.uid = generate_uid(data[10:])

      writer.write(b'YAFN TRACKER CHECK' + b'\x00' * 154)
      await asyncio.wait_for(
        writer.drain(),
        timeout=5
      )
    except:
      self.failed_checks += 1
      self.works = False

      return False
    finally:
      try:
        writer.close()
        await asyncio.wait_for(
          writer.wait_closed(),
          timeout=2
        )
      except:
        pass

    self.failed_checks = 0
    self.works = True
    self.latency = time.time() - self.last_check

    return True

class Tracker:
  def __init__(self):
    self.peers = []

  async def add(self, addr):
    for peer in self.peers:
      if peer.addr == addr:
        return await peer.check()

    peer = Peer(addr)
    if await peer.check():
      self.peers.append(peer)

      return True

    return False

  async def watch(self):
    while True:
      to_delete = []

      for peer in self.peers:
        if not await peer.check():
          if peer.failed_checks >= 3:
            to_delete.append(peer)

      for peer in to_delete:
        self.peers.remove(peer)

      await asyncio.sleep(60)

tracker = Tracker()

async def request_handler(request):
  remote_addr = request.headers.get('YAFN-Remote-Address', request.remote)

  is_accessible = await tracker.add(remote_addr)
  peers = tracker.peers.copy()
  peers = [
    {
      'address': peer.addr,
      'uid': peer.uid,
      'latency': int(peer.latency),
      'last_check': int(peer.last_check)
    } for peer in peers if peer.works and peer.addr != remote_addr
  ]
  peers.sort(key=lambda peer: (peer['last_check'], peer['latency']))

  return web.Response(
    body=cbor2.dumps({
      'remote_addr': remote_addr,
      'is_accessible': is_accessible,
      'peers': peers
    })
  )

async def main():
  asyncio.ensure_future(tracker.watch())

  app = web.Application()
  app.add_routes([
    web.get('/track', request_handler),
  ])

  return app

web.run_app(main(), port=49873)
