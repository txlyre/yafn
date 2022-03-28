from setuptools import setup

setup(
  name='YAFN',
  version='0.0.1',
  author='txlyre',
  author_email='me@txlyre.website',
  packages=['yafn', 'yafn-tracker'],
  url='https://github.com/txlyre/yafn',
  license='LICENSE',
  description='Yet another p2p file network protocol.',
  install_requires=[
    'cbor2',
    'pyzmq',
    'pyvis',
    'aiohttp',
    'pycryptodome',
  ],
)