package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */

public class Router extends Device
{	
	private static final byte TYPE_TIME_EXCEEDED = 11;
	private static final byte TYPE_DESTINATION_UNREACHABLE = 3;
	private static final byte TYPE_ECHO_REPLY = 0;
	private static final byte BROADCAST[] = {127, 127, 127, 127, 127, 127};
	private static final byte CODE_TIME_EXCEEDED = 0;
	private static final byte CODE_NET_UNREACHABLE = 0;
	private static final byte CODE_HOST_UNREACHABLE = 1;
	private static final byte CODE_PORT_UNREACHABLE = 3;
	private static final byte CODE_ECHO_REPLY = 0;
	private static final String RIP_MULTICAST_ADDR = "224.0.0.9";
	private static final int ROUTE_ENTRY_EXPIRATION_TIME = 30 * 1000;
	private static final int BROADCAST_RIP_TABLE_ENTRIES = 10 * 1000;
			
	Timer timer = new Timer();

	Map<Integer, UnknownQueue> map = new ConcurrentHashMap<Integer, UnknownQueue>();
	public Hashtable<Integer ,RIPv2Entry> ripTable = new Hashtable<Integer, RIPv2Entry>();
	
	/** Routing table for the router */
	public RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	public void runRipv2(){
		routeTable = new RouteTable();
		initializeRipTable();
		broadcastRIP(RIPv2.COMMAND_REQUEST);
		RipBroadcastTask ripBroadcast = new RipBroadcastTask(this);
		timer.schedule(ripBroadcast, BROADCAST_RIP_TABLE_ENTRIES, BROADCAST_RIP_TABLE_ENTRIES);
	}
	
	// adds all the reachable subnets of the routers interfaces to the route
	// table and to our rip table
	private void initializeRipTable(){
		int gateway = 0;
		int metric = 1; //can reach at distance 1		
		Map<String, Iface> ifaces = this.interfaces;
		
		//go over each entry and grab its info to construct ripEntry
		//ALSO NEED TO ADD EACH ENTRY TO ROUTE TABLE
		for(Entry<String, Iface> entry : ifaces.entrySet()){
			Iface iface = entry.getValue();
			int dstIp = iface.getIpAddress();
			int maskIp = iface.getSubnetMask();
			//int Subnet = dstIp & maskIp;
			
			RIPv2Entry ripEntry = new RIPv2Entry();
			ripEntry = new RIPv2Entry(dstIp, maskIp, metric);
			ripTable.put(dstIp, ripEntry);
			
			// Also add the entries to our routeTable
			routeTable.insert((dstIp & maskIp), gateway, maskIp, iface);
			System.out.println("Initialize route table with my interfaces");
		}
	}
	// remove entry from rip table and route table
	public void expireRouteEntry(int dst, int mask){

		//toExpire.getTimerTask().cancel();
		//timer.purge();
		ripTable.remove(dst);
		routeTable.remove((dst & mask), mask);
		System.out.println("remove from my route table. entry expired");
		System.out.println(routeTable.toString());
	}
	
	private void broadcastRIP(byte ripCommand){
		Map<String, Iface> ifaces = this.interfaces;
		
		System.out.println(routeTable.toString());
		
		for(Entry<String, Iface> entry : ifaces.entrySet()){
			MACAddress srcMAC = entry.getValue().getMacAddress();
			int srcIP = entry.getValue().getIpAddress();
			Ethernet ripPacket = setupRipPacket(ripCommand, srcIP, srcMAC);
			sendPacket(ripPacket, entry.getValue());
		}
	}
	
	private Ethernet setupRipPacket(byte ripCommand, int srcIP, MACAddress srcMAC){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		//link packets together
		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);

		//ethernet layer
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress(BROADCAST);
		ether.setSourceMACAddress(srcMAC.toBytes());

		//ip layer
		ip.setSourceAddress(srcIP);
		ip.setDestinationAddress(RIP_MULTICAST_ADDR);
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		//udp layer
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		//set up rip
		rip.setCommand(ripCommand);
		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>(ripTable.values());
		rip.setEntries(entries);
		
		//reset checksums
		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		
		return ether;
	}
	
	private void handleRipPacket(RIPv2 ripPacket, Iface inIface) {
		boolean sendTable = false;
		boolean sendResponse = true;
		
		if(ripPacket.getCommand() == RIPv2.COMMAND_REQUEST){
			sendResponse = true;
		}
		
		List<RIPv2Entry> newRipEntries = ripPacket.getEntries();
		for(RIPv2Entry entry : newRipEntries){
			
			if(ripTable.containsKey(entry.getAddress())){
				int currentMetric = ripTable.get(entry.getAddress()).getMetric();
				int newMetric = entry.getMetric() + 1;
				
				if(newMetric < currentMetric){
					ripTable.remove(entry.getAddress());
					if(newMetric < 16){
						sendTable = updateRipEntry(entry, inIface);
					}
				}
			}
			else{
				sendTable = updateRipEntry(entry, inIface);
			}
		}
		
		if(sendTable){
			broadcastRIP(RIPv2.COMMAND_RESPONSE);
		}
		else if(sendResponse){
			Ethernet ripPacketResponse = setupRipPacket(RIPv2.COMMAND_RESPONSE, inIface.getIpAddress(), inIface.getMacAddress());
			sendPacket(ripPacketResponse, inIface);
		}
	}
	
	private boolean updateRipEntry(RIPv2Entry entry, Iface inIface){
		
		ExpireRouteEntryTask newTask = null;
		//increase hop count and update rip table
		int metric = entry.getMetric()+1;
		if(metric > 16){
			metric = 16;
		}
		entry.setMetric(metric);
		System.out.println("We are updating our rip table with info from otehr routers");
		ripTable.put(entry.getAddress(), entry);
		
		RouteEntry rEntry = routeTable.lookup(entry.getAddress());
		//update route table
		if(rEntry != null){
			//in table already
			rEntry.setInterface(inIface);
			rEntry.setSubnetAddress(entry.getSubnetMask());
			rEntry.setGatewayAddress(entry.getNextHopAddress());
			ExpireRouteEntryTask atask = rEntry.getTimerTask();
			if(atask != null){
				atask.cancel();
				timer.purge();
				newTask = new ExpireRouteEntryTask(this, rEntry.getDestinationAddress(), rEntry.getMaskAddress());
				rEntry.resetTimerTask(newTask);
			}
		}
		else{
			//add new entry
			newTask = new ExpireRouteEntryTask(this, entry.getAddress(), entry.getSubnetMask());
			routeTable.insert((entry.getAddress() & entry.getSubnetMask()), inIface.getIpAddress(), inIface.getSubnetMask(), inIface, newTask);
		}
		if(newTask != null)
			timer.schedule(newTask, ROUTE_ENTRY_EXPIRATION_TIME);
		return true;
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		//System.out.println("*** -> Received packet: " +
		//		etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/

		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;

		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		}
		// Ignore all other packet types, for now

		/********************************************************************/
	}

	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {

		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		// Make sure it's an ARP Request
		if (arpPacket.getOpCode() == ARP.OP_REQUEST){
			System.out.println("We have an ARP Request");
			
			int dstIP = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
			MACAddress dstMAC = MACAddress.valueOf(arpPacket.getSenderHardwareAddress());
			arpCache.insert(dstMAC, dstIP);
			// Only respond to ARP requests whose target IP equals IP of 
			// interface on which the ARP request was received.
			if(targetIp == inIface.getIpAddress()){

				Ethernet ether = new Ethernet();
				ARP arp = new ARP();
				//link the headers together
				ether.setPayload(arp);

				//Ethernet Header
				ether.setEtherType(Ethernet.TYPE_ARP);
				ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
				ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

				//ARP Header
				arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arp.setProtocolType(ARP.PROTO_TYPE_IP);
				arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
				arp.setProtocolAddressLength((byte) 4);
				arp.setOpCode(ARP.OP_REPLY);

				//sender
				arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
				arp.setSenderProtocolAddress(inIface.getIpAddress());

				//target
				arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
				arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

				ether.resetChecksum();
				sendPacket(ether, inIface);
			}
		}
		else if( arpPacket.getOpCode() == ARP.OP_REPLY){
			System.out.println("ARP Reply");

			int dstIP = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
			MACAddress dstMAC = MACAddress.valueOf(arpPacket.getSenderHardwareAddress());

			// insert arpCache entry for the corresponding ARP reply
			arpCache.insert(dstMAC, dstIP);

			//dequeue the packets and enter the destination MAC
			UnknownQueue foundHost = map.get(dstIP);
			if(foundHost != null){
				//cancel any pending arp timer tasks since we got the information we needed
				foundHost.getArpTask().cancel();
				//remove the scheduled tasks from the timer
				timer.purge();
				//send all of the stored messages that are destined for the newly found host
				Queue<Ethernet> messages = foundHost.getQueue();
				for(Ethernet msg : messages){
					System.out.println("We found the host! Send some packets!");
					msg.setDestinationMACAddress(dstMAC.toBytes());
					sendPacket(msg, this.getOutIface(msg));
				}
				map.remove(dstIP);	
			}
		}
	}

	private void handleArpCacheMiss(RouteEntry bestMatch, int nextHop, Ethernet etherPacket, Iface inIface, IPv4 ipkt) {

		// If our map already has the destination address in it add message to queue
		if(map.containsKey(ipkt.getDestinationAddress())){
			// We need to add the message to our queue
			System.out.println("Adding new message to existing queue");
			UnknownQueue unknownHost = map.get(ipkt.getDestinationAddress());
			unknownHost.getQueue().add(etherPacket);
		}
		//generate ARP request and broadcast it on all non-incoming interfaces
		else{
			int timeBeforeResend = 1000; // 1 second
			Ethernet arpRequest = generateArpRequestPacket(nextHop, inIface);

			/*Construct new object*/
			ARPTask sendARPTask = new ARPTask(arpRequest, bestMatch.getInterface() , ipkt.getDestinationAddress());
			UnknownQueue unknownHostInfo = new UnknownQueue(etherPacket, sendARPTask);

			//get destination IP and add the corresponding UnknownQueue to the map
			map.put(ipkt.getDestinationAddress(), unknownHostInfo);

			//Schedule the task to go off in 1 second
			timer.schedule(sendARPTask, timeBeforeResend, timeBeforeResend);

			sendPacket(arpRequest, bestMatch.getInterface());
		}
	}

	private Ethernet generateArpRequestPacket(int nextHop, Iface inIface) {
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();

		//link the headers together
		ether.setPayload(arp);

		//Ethernet Header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		//ether.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
		ether.setDestinationMACAddress(BROADCAST);

		//ARP Header
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REQUEST);

		//sender
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());

		//target
		byte unknown[] = {0, 0, 0, 0, 0, 0};
		arp.setTargetHardwareAddress(unknown);
		arp.setTargetProtocolAddress(nextHop);

		ether.resetChecksum();

		return ether;
	}
	
	private void checkIfContinueTryingToSendArpPacket(Ethernet arpRequestPacket, Iface outIface, int dstIP){
		UnknownQueue unknownHost = map.get(dstIP);
		// Send the message up to 3 times
		if(unknownHost.getTimesSent() < 3){
			unknownHost.incrementTimesSent();
			sendPacket(arpRequestPacket, outIface);
		}
		// If it has already been sent 3 times, don't reschedule the timer
		else{
			IPv4 ipPacket;
			//cancel timertask
			unknownHost.getArpTask().cancel();
			//purge timer
			timer.purge();
			//flush queue //send dst host unreachable
			Queue<Ethernet> messages = unknownHost.getQueue();
			System.out.println("size of queue" + messages.size());
			//Ethernet msg;
			for(Ethernet msg : messages){
				//for(int i = 0; i < messages.size(); i++){
				//msg = messages.remove();
				ipPacket = (IPv4) msg.getPayload();
				sendICMPmessage(TYPE_DESTINATION_UNREACHABLE, CODE_HOST_UNREACHABLE, msg, this.getInIface(msg), ipPacket);
				System.out.println("SEND ICMP MSG");
			}
			System.out.println("we sent all the messages in the queue!!! woohooo!");
			
			//remove dstIP from map
			map.remove(unknownHost);
		}
	}

	private Iface getOutIface(Ethernet etherPacket) {
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		return bestMatch.getInterface();
	}
	
	private Iface getInIface(Ethernet etherPacket){

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getSourceAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		return bestMatch.getInterface();
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		//System.out.println("Handle IP packet");
		
		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{ 
			sendICMPmessage(TYPE_TIME_EXCEEDED, CODE_TIME_EXCEEDED, etherPacket, inIface, ipPacket);
			return; 
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();
		
		//handle rip packet
		if((ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) && 
		   (ipPacket.getDestinationAddress() == IPv4.toIPv4Address(RIP_MULTICAST_ADDR))){
			UDP udpPacket = (UDP) ipPacket.getPayload();
			if(udpPacket.getSourcePort() == UDP.RIP_PORT){
				RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
				handleRipPacket(ripPacket, inIface);
				return;
			}	
		}
		
		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{ 
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || 
						ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
					sendICMPmessage(TYPE_DESTINATION_UNREACHABLE, CODE_PORT_UNREACHABLE, etherPacket, inIface, ipPacket);

				}
				else if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){
					ICMP icmpPacket = (ICMP)ipPacket.getPayload();
					if(icmpPacket.getIcmpCode() == ICMP.TYPE_ECHO_REQUEST){
						System.out.println("ever have an echo request?");
						sendICMPmessage(TYPE_ECHO_REPLY, CODE_ECHO_REPLY, etherPacket, inIface, ipPacket);
					}
				}
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{ 
			sendICMPmessage(TYPE_DESTINATION_UNREACHABLE, CODE_NET_UNREACHABLE, etherPacket, inIface, ipPacket);
			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{ 
			// This is temporarily commented out so that we can send an arp request
			//sendICMPmessage(TYPE_DESTINATION_UNREACHABLE, CODE_HOST_UNREACHABLE, etherPacket, inIface, ipPacket);
			//
			//Also need to do some sort of queueing per IP addr
			handleArpCacheMiss(bestMatch, nextHop, etherPacket, inIface, ipPacket);
			return; 
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	private void sendICMPmessage(byte type, byte code, Ethernet etherPacket, Iface inIface, IPv4 ipPacket){
		//send ICMP Time Exceeded message
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();

		//Link the headers together
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		////Find destination MAC
		// Get IP header
		ipPacket.resetChecksum();
		int srcAddr = ipPacket.getSourceAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(srcAddr);;

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = srcAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);

		//Update Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		// this is the case for Arp Request timeout
		if(arpEntry == null){
			//ether.setDestinationMACAddress(inIface.getMacAddress().toBytes());
			ether.setDestinationMACAddress(etherPacket.getSourceMAC().toBytes());
			System.out.println("We have a null arp entry");
		}
		else{
			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		}

		//Update IP header
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		//Update the data
		if(type == TYPE_ECHO_REPLY){
			System.out.println("does the type ever equal an echo reply?");
			ICMP icmpPacket = (ICMP)ipPacket.getPayload();
			icmp = icmpPacket;	
			//special case for echo reply
			ip.setSourceAddress(ipPacket.getDestinationAddress());
			System.out.println("ipPacket destination = " + ipPacket.getDestinationAddress());
		}
		else{
			byte headerLength = ipPacket.getHeaderLength();
			ipPacket.resetChecksum();
			byte ipInfo[] = ipPacket.serialize();
			byte padding[] = {0, 0, 0, 0}; 
			byte dataPayload[] = new byte[(byte)padding.length + (byte)(headerLength * 4) + (byte) 8];

			for(int i = 0; i < dataPayload.length; i++){
				if(i < padding.length){
					dataPayload[i] = padding[i];
				}
				else{
					dataPayload[i] = ipInfo[i-padding.length];
				}
			}
			data.setData(dataPayload);
		}

		//Update ICMP header
		icmp.setIcmpCode(code);
		icmp.setIcmpType(type);

		icmp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		System.out.println("send ICMP Packet");
		sendPacket(ether, inIface);
		System.out.println("ICMP sent!!");
	}

	class ARPTask extends TimerTask {
		private Ethernet ether;
		private Iface inIface;
		private int dstIP;

		public ARPTask(Ethernet ePacket, Iface i, int ip){
			ether = ePacket;
			dstIP = ip;
			inIface = i;
		}
		@Override
		public void run() {
			System.out.println("Resend ARP Request");
			checkIfContinueTryingToSendArpPacket(ether, inIface, dstIP);
		}
	}
	
	class ExpireRouteEntryTask extends TimerTask {
		private Router router;
		private int dstAddr, maskAddr;
		public ExpireRouteEntryTask(Router r, int dst, int mask){
			router = r;
			dstAddr = dst;
			maskAddr = mask;
		}

		@Override
		public void run() {
			router.expireRouteEntry(dstAddr, maskAddr);
		}
	}
	
	class RipBroadcastTask extends TimerTask {
		private Router router;

		public RipBroadcastTask(Router r){
			router = r;
		}
		@Override
		public void run() {
			router.broadcastRIP(RIPv2.COMMAND_RESPONSE);
		}
	}
}


