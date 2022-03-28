# YAFN
Yet Another p2p File Network. JFF implementation of a tiny peer-to-peer file sharing protocol.  

# Installation
Python>=3.6 is required.  
Run `pip install --upgrade git+https://github.com/txlyre/yafn.git` to install or update the YAFN.  

# Usage
- `python -m yafn -S`: start up a YAFN peer. In order to find out other peers on the network add some trackers (e.g. `rocks.txlyre.website`) to the `trackers.txt` file located in `(your home directory)/yafn/`. 
- `python -m yafn -s <path>`: share a file (you will get a .ynmf metafile - use it to get the file after).  
- `python -m yafn -q <metafile.ynmf>`: query a file described by the supplied metafile.  

Run `python -m yafn --help` to get more information on usage.
