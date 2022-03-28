import os
import os.path
import sys
import math
import time
import atexit
import struct
import argparse

from pathlib import Path

from . import log
from . import yafn

from pyvis.network import Network

class Progress:
  def __init__(self, max):
    self.max = max

    self.CHARS = ('/', '-', '\\', '|')

    self.index = 0
    self.length = 0
    self.ready = 0

    self._display(0)

  def _render(self):
    text = f'{self.ready}/{self.max} piece{"s" if self.ready != 1 else ""} ready ... {self.CHARS[self.index]}\n'
    
    self.index += 1

    if self.index == len(self.CHARS):
      self.index = 0

    self.length = len(text)

    return text

  def _display(self, ready):
    text = self._render()

    sys.stdout.write(text)
    sys.stdout.flush() 

  def update(self, ready):
    self.ready += ready

    sys.stdout.write("\033[F")
    sys.stdout.write("\033[K")
    sys.stdout.write(self._render())
    sys.stdout.flush() 

class Metafile:
  HEADER = b'\x80YAFN-METAFILE\x00\x00'
  HEADER_LEN = len(HEADER)

  def __init__(self, filename, size, pieces):
    self.filename = filename
    self.size = size
    self.pieces = pieces

  def save(self, path):
    with open(path, 'wb') as f:
      f.write(Metafile.HEADER)

      filename = self.filename.encode('UTF-8')
      filename_len = len(filename)
  
      f.write(struct.pack('!I', filename_len))
      f.write(filename)

      f.write(struct.pack('!L', self.size))

      pieces_count = len(self.pieces)

      f.write(struct.pack('!L', pieces_count))
    
      for hash in self.pieces:
        f.write(hash)

  @staticmethod
  def load(path):
    with open(path, 'rb') as f:
      header = f.read(Metafile.HEADER_LEN)
      if header != Metafile.HEADER:
        raise ValueError

      filename_len = f.read(4)
      filename_len = struct.unpack('!I', filename_len)[0]

      filename = f.read(filename_len)
      filename = filename.decode('UTF-8')
      filename = Path(filename).name

      size = f.read(4)
      size = struct.unpack('!I', size)[0]

      pieces_count = f.read(4)
      pieces_count = struct.unpack('!L', pieces_count)[0]

      if pieces_count < 1:
        raise ValueError

      pieces = []

      while pieces_count > 0:
        piece_hash = f.read(76)
        if len(piece_hash) != 76:
          raise ValueError

        pieces.append(piece_hash)

        pieces_count -= 1

    return Metafile(filename, size, pieces)

COLORS = [
  (0,   255, 0),
  (255, 255, 0),
  (255, 0,   0)
]

def pick_color(index):
  index = min(index, 10) * 0.1
  n3 = 0

  if index <= 0:
    n1 = 0
    n2 = 0
  elif index >= 1:
    n1 = len(COLORS) - 1
    n2 = len(COLORS) - 1
  else:
    index = index * (len(COLORS) - 1)
    n1 = math.floor(index)
    n2 = n1 + 1
    n3 = index - n1

  color = (
    (COLORS[n2][0] - COLORS[n1][0]) * n3 + COLORS[n1][0],
    (COLORS[n2][1] - COLORS[n1][1]) * n3 + COLORS[n1][1],
    (COLORS[n2][2] - COLORS[n1][2]) * n3 + COLORS[n1][2]
  )

  return f'#{int(color[0]):02x}{int(color[1]):02x}{int(color[2]):02x}'

def distance(graph, start, end):
  visited = []
  queue = [[start]]

  if start == end:
    return 0

  while queue:
    path = queue.pop(0)
    node = path[-1]

    if node not in visited:
      near = graph[node]

      for near_node in near:
        if near_node == end:
          return len(path)

        queue.append(path + [near_node])

      visited.append(node)

  return 10

def build_graph(graph, map, first=False):
  uid = yafn.encode_uid(map.uid)

  graph.add_node(
    uid,
    label=f'{uid[:6]}{" (this peer)" if first else ""}',
    title=uid
  )

  for submap in map.submaps:
    subuid = build_graph(graph, submap)
    
    graph.add_edge(uid, subuid)

  return uid

parser = argparse.ArgumentParser()
parser.add_argument(
  '-S', '--start',
  help='Start up the local peer.',
  action='store_true'
)

parser.add_argument(
  '-a', '--address',
  help='Set a custom external address.',
  type=str
)

parser.add_argument(
  '-o', '--out',
  help='Specify a path for the output.',
  action='append',
  type=str
)

parser.add_argument(
  '-C', '--cleanup',
  help='Remove all old pieces.',
  action='store_true'
)

parser.add_argument(
  '-c', '--crawl',
  help='Create a map of the network.',
  action='store_true'
)

parser.add_argument(
  '-d', '--discover',
  help='Send a discover request to the local peer.',
  action='store_true'
)

parser.add_argument(
  '-s', '--share',
  help='Share a file to the network',
  action='append',
  type=str,
  metavar='PATH'
)

parser.add_argument(
  '-q', '--query',
  help='Query a file from the network',
  action='append',
  type=str,
  metavar='METAFILE'
)

args = parser.parse_args()

if args.cleanup or args.crawl or args.discover or args.share or args.query:
  interface = yafn.Interface.connect()

  atexit.register(interface.close)
  
if args.out:
  total_size = 0
  
  if args.share:
    total_size += len(args.share)
    
  if args.query:
    total_size += len(args.query)
    
  if len(args.out) != total_size:
    log.fatal('Count of the -o arguments doesn\'t match the count of -q/-s arguments.')

  out_index = 0
  
if args.cleanup:
  log.info('Cleaning up...')
    
  if interface.cleanup():
    log.info('Done.')
  else:
    log.error('Cleaning up failed.')

if args.crawl:
  log.info(f'Building a map of the network...')

  map = interface.crawl()
  if not map:
    log.fatal('Failed to crawl the network.')
 
  network = Network(
    height='100%',
    width='100%',
    bgcolor='#222222',
    font_color='white'
  )

  first_uid = build_graph(network, map, first=True)

  adj_list = network.get_adj_list()
  for node in network.nodes:
    node['value'] = min(max(len(adj_list[node['id']]), 1), 10)
    node['color'] = pick_color(distance(adj_list, first_uid, node['id']))

  filename = f'map_{int(time.time())}.html'
  network.save_graph(filename)

  log.info(f'Network map is saved as \'{filename}\'.')
  
if args.discover:
  log.info('Discovering the network...')
    
  if interface.discover():
    log.info('Done.')
  else:
    log.error('Discovering failed.')
  
if args.share:
  for path in args.share:
    out_index += 1
    
    if not os.path.isfile(path):
      log.fatal(f'Not a valid file: \'{path}\'.')

    log.info(f'Share \'{path}\'.')

    with open(path, 'rb') as f:
      progress = Progress('_')
      pieces = []
      size = 0

      while True:
        piece = f.read(yafn.Piece.PIECE_SIZE)
        if not piece:
          break

        hash = interface.save(piece)
        if not hash:
          log.error('Failed to save a piece.')

          continue

        pieces.append(hash)
        progress.update(1)

        size += len(piece)

    filename = os.path.basename(path)
    metafile_name = args.out[out_index - 1] if args.out else f'{filename}.ynmf'

    metafile = Metafile(
      filename,
      size,
      pieces
    )

    try:
      metafile.save(metafile_name)
    except:
      log.fatal('Failed to save the metafile.')

    log.info(f'Metafile is saved as \'{metafile_name}\'.')

    log.info('Announcing the neighbour peers...')
    
    if interface.announce():
      log.info('Done.')
    else:
      log.error('Announcing failed.')
 
if args.query:
  for path in args.query:
    out_index += 1
    
    try:
      metafile = Metafile.load(path)
    except:
      log.fatal(f'Cannot open metafile: \'{path}\'.')

    log.info(f'Query \'{metafile.filename}\'.')

    filename = args.out[out_index - 1] if args.out else metafile.filename

    try:
      with open(filename, 'wb') as f:
        progress = Progress(len(metafile.pieces))

        for hash in metafile.pieces:
          piece = interface.query(hash)
          if not piece:
            log.error(f'Piece {hash[:32].hex()} is not available.')

            continue

          f.write(piece)
          progress.update(1)
    except IOError as error:
      log.fatal(f'Failed to open output file: {error}')

    log.info(f'File is saved as \'{filename}\'.')

if args.start:
  peer = yafn.Peer()
  peer.start(remote_addr=args.address)
