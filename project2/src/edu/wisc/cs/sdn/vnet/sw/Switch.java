package edu.wisc.cs.sdn.vnet.sw;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	HashMap<MACAddress, SwitchEntry> switchTable = new HashMap<MACAddress, SwitchEntry>();
	Timer timer = new Timer();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		////////////////////////VARIABLE DECLARATIONS///////////////////////////
		MACAddress src = etherPacket.getSourceMAC();
		MACAddress dst = etherPacket.getDestinationMAC();
		SwitchEntry incomingInfo;
		int timeToLive = 15 *1000; //15 seconds to expire for Switch Entries
		
		CacheTask expirationTask = new CacheTask(src, this);

		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		////////////////////////////UPDATE SWITCH TABLE/////////////////////////
		if(switchTable.containsKey(src)){
			SwitchEntry itemToBeUpdtated = switchTable.get(src);
			itemToBeUpdtated.getCacheTask().cancel();
			timer.purge();
			itemToBeUpdtated.updateExpireTime(expirationTask);
			timer.schedule(expirationTask, timeToLive);
		}
		else{
			System.out.println("added entry!");
			incomingInfo = new SwitchEntry(src, inIface, expirationTask);
			switchTable.put(src, incomingInfo);
			timer.schedule(expirationTask, timeToLive);
		}

		////////////////////////////SEND PACKET/////////////////////////////////
		/*If our destination MAC is in the switch table, then we know where
		 *to send it*/
		if(switchTable.containsKey(dst)){
			sendPacket(etherPacket, switchTable.get(dst).getIface());
		}
		/*Otherwise we need to broadcast*/
		else{
			Iface port;
			Map<String, Iface> interfaces = this.getInterfaces();
			for(Map.Entry<String, Iface> item : interfaces.entrySet()){
				port = item.getValue();
				/*We don't want to send back to the interface that sent us 
				 *the packet*/
				if(!(port.equals(inIface))){
					sendPacket(etherPacket, port);
				}	
			}	
		}
	}

	/**cleanCacheEntry is called when a timer expires. This is used to remove
	 *expired entries from the switch table
	 *
	 *@param expiredEntry is the MAC address associated with the bad entry
	 */

	public void cleanCacheEntry(MACAddress expiredEntry) {
		switchTable.remove(expiredEntry);	
	}
}

/**CacheTask is the timer task associated with our Switch Entries. This calls
 *the cleanCacheEntry function that will remove the expired item from the
 *switch table
 */
class CacheTask extends TimerTask{
	private MACAddress expired;
	private Switch ourSwitch;

	public CacheTask(MACAddress src, Switch s1) {
		expired = src;
		ourSwitch = s1;
	}

	@Override
	public void run() {
		System.out.println("Remove item " + expired +" is removed from cache");
		ourSwitch.cleanCacheEntry(expired);	
	}
}
