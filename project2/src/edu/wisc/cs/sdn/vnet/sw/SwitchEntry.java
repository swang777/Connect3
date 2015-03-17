package edu.wisc.cs.sdn.vnet.sw;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

public class SwitchEntry {
	MACAddress MAC;
	Iface port;
	CacheTask expireTime;
	
	public SwitchEntry(MACAddress src, Iface inIface, CacheTask expire){
		MAC = src;
		port = inIface;
		expireTime = expire;
	}
	
	public MACAddress getMAC(){
		return this.MAC;
	}
	
	public Iface getIface(){
		return this.port;
	}
	
	public CacheTask getCacheTask(){
		return this.expireTime;
	}
	public void updateExpireTime(CacheTask time){
		expireTime = time;
	}
}

