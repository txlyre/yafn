import sys
import logging

logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)

def info(message):
  logging.info(message)

def warning(message):
  logging.warning(message)

def error(message):
  logging.error(message)

def fatal(message):
  logging.error(message)

  sys.exit(1)
