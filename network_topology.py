#!/usr/bin/python

import sys
import time
import math

from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, adhoc
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mn_wifi.wmediumdConnector import error_prob
from mn_wifi.node import CPULimitedStation

class TopologyGenerator:
  def __init__(self,width=3,height=3):
    self.x=width;
    self.y=height;
    
  def params(self,args):
    self.cpu_rate_flag=False
    for param in args:
      if param.startswith("-w"):
        self.x=int(param.split(":")[1]);
      if param.startswith("-h"):
        self.y=int(param.split(":")[1]);
      
    print("w:"+str(self.x)+" h:"+str(self.y));

  def generate(self):
    #net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference,noise_th=-91, fading_cof=1)
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    #net = Mininet_wifi(link=wmediumd)
    num=self.x*self.y;
    
    info("*** Creating nodes\n")
    self.stas = []

    print("*** Creating nodes")
    interval=70;
    #sta1 = net.addStation('sta1', ip6='fe80::1',cls=CPULimitedStation,position='10,10,0', **kwargs)
    #sta1.setCPUFrac(f=0.01)
    for i in range(num):
        if(self.cpu_rate_flag):
            sta = net.addStation('sta' + str(i+1), cls=CPULimitedStation, position=str(i%self.x*interval)+','+str(math.floor(i/self.x)*interval)+',0', range=100)
            sta.setCPUFrac(f=float(self.cpu_rate))
            self.stas.append(sta)
        else:
            self.stas.append(net.addStation('sta' + str(i+1), position=str(i%self.x*interval)+','+str(math.floor(i/self.x)*interval)+',0', range=100))
		
    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=4)

    print("*** Configuring wifi nodes")
    net.configureWifiNodes()

    print("*** Creating links")
    for i in range(num):
        net.addLink(self.stas[i], cls=adhoc, intf='sta'+str(i+1)+'-wlan0',ssid='adhocNet',mode='g', channel=5, ht_cap='HT40+')
        #net.addLink(self.stas[i], cls=adhoc, intf='sta'+str(i+1)+'-wlan0',ssid='adhocNet',mode='g', channel=5)
    net.plotGraph(max_x=800, max_y=800)

    return net;

  def run(self,net):
    
    info("*** Starting network\n")
    net.build()

    #self.sendCommand();
    #self.writeCommand();
    info("*** Running CLI\n")
    time.sleep(0.5);
    cliwifi=CLI(net)
    info("*** Stopping network\n")
    net.stop()
    
  def setPromisc(self):
    info("*** Interface configuration ***")
    num=self.x*self.y;
    for i in range(num):
      self.stas[i].cmd('ifconfig sta'+str(i+1)+'-wlan0 promisc');
      self.stas[i].cmd('iwconfig sta'+str(i+1)+'-wlan0 rts off');
      self.stas[i].cmd('iwconfig sta'+str(i+1)+'-wlan0 retry max 1');

  def command_source(self,cmd):
    self.stas[0].cmd('xterm -hold -e '+cmd);

if __name__ == '__main__':
  setLogLevel('info')
  args=sys.argv;

  if len(args) != 4:
    print("usage python location.py -w:width -h:height -p:protocol ");
  
  topo=TopologyGenerator();
  topo.params(args);
  net=topo.generate();
  #topo.setPromisc();
  topo.run(net);
  #topo.command('java -cp ./bin ou.ist.de.Main -protocol:DSR -port:10000 -frag:1000 &');
