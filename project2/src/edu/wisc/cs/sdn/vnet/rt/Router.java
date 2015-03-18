package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Arrays;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */

public class Router extends Device
{	
	public static final byte TYPE_TIME_EXCEEDED = 11;
	public static final byte TYPE_DESTINATION_UNREACHABLE = 3;
	public static final byte TYPE_ECHO_REPLY = 0;
	
	public static final byte CODE_TIME_EXCEEDED = 0;
	public static final byte CODE_NET_UNREACHABLE = 0;
	public static final byte CODE_HOST_UNREACHABLE = 1;
	public static final byte CODE_PORT_UNREACHABLE = 3;
	public static final byte CODE_ECHO_REPLY = 0;
	
	/** Routing table for the router */
	private RouteTable routeTable;
	
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
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
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
		// Make sure it's an ARP Request
		System.out.println("Handling ARP Packet");
		if (arpPacket.getOpCode() == ARP.OP_REQUEST){
			System.out.println("We have an ARP Request");
			// Only respond to ARP requests whose target IP equals IP of 
			// interface on which the ARP request was received.
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
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
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

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
        	sendICMPmessage(TYPE_DESTINATION_UNREACHABLE, CODE_HOST_UNREACHABLE, etherPacket, inIface, ipPacket);
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
    	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
    	
    	//Update IP header
    	ip.setTtl((byte) 64);
    	ip.setProtocol(IPv4.PROTOCOL_ICMP);
    	ip.setSourceAddress(inIface.getIpAddress());
    	ip.setDestinationAddress(ipPacket.getSourceAddress());
    	
    	//Updata the data
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
    	sendPacket(ether, inIface);
    }
}
