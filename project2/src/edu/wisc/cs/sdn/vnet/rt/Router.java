package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	public static final byte ICMP_TIMEOUT_CODE = 0;
	public static final byte ICMP_TIMEOUT_TYPE = 11;
	public static final byte ICMP_HOST_NOT_REACHABLE_TYPE = 3;
	public static final byte ICMP_HOST_NOT_REACHABLE_CODE = 0;
	public static final byte ICMP_PORT_NOT_REACHABLE_TYPE = 3;
	public static final byte ICMP_PORT_NOT_REACHABLE_CODE = 3;
	public static final byte ICMP_ECHO_REPLY_TYPE = 0;
	public static final byte ICMP_ECHO_REPLY_CODE = 0;
	private static final int ROUTE_ENTRY_EXPIRATION_TIME = 30000;
	private static final int BROADCAST_RIP_TABLE_ENTRIES = 10000;
	private static final byte BROADCAST[] = { 127, 127, 127, 127, 127, 127 };

	Timer timer = new Timer();
	public HashMap<Integer, RIPv2Entry> ripTable = new HashMap<Integer, RIPv2Entry>();
	Map<Integer, UnknownQueue> Arp_map = new ConcurrentHashMap<Integer, UnknownQueue>();

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	public void loadRipv2() {
		routeTable = new RouteTable();
		initializeRipTable();
		broadcastRIP(RIPv2.COMMAND_REQUEST);
		RipBroadcastTask ripBroadcast = new RipBroadcastTask(this);
		timer.schedule(ripBroadcast, BROADCAST_RIP_TABLE_ENTRIES, BROADCAST_RIP_TABLE_ENTRIES);
	}

	// adds all the reachable subnets of the routers interfaces to the route
	// table and to our rip table
	private void initializeRipTable() {
		Map<String, Iface> ifaces = this.interfaces;
		for (String key : ifaces.keySet()) {
			Iface iface = ifaces.get(key);
			int dstIp = iface.getIpAddress();
			int maskIp = iface.getSubnetMask();

			RIPv2Entry ripEntry = new RIPv2Entry(dstIp, maskIp, 1);
			ripTable.put(dstIp, ripEntry);
			routeTable.insert((dstIp & maskIp), 0, maskIp, iface);
			System.out.println("Initialize");
		}
	}

	private void broadcastRIP(byte ripCommand) {
		Map<String, Iface> ifaces = this.interfaces;

		for (String key : ifaces.keySet()) {
			MACAddress srcMAC = ifaces.get(key).getMacAddress();
			int srcIP = ifaces.get(key).getIpAddress();
			Ethernet packet = setupRipPacket(ripCommand, srcIP, srcMAC);
			sendPacket(packet, ifaces.get(key));
		}
	}

	private Ethernet setupRipPacket(byte ripCommand, int srcIP, MACAddress srcMAC) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		RIPv2 rip = new RIPv2();
		UDP udp = new UDP();

		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress(BROADCAST);
		ether.setSourceMACAddress(srcMAC.toBytes());

		if (ip == null) {
			System.out.println("no ip");
		}
		ip.setSourceAddress(srcIP);
		ip.setDestinationAddress("224.0.0.9");
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		rip.setCommand(ripCommand);

		if (ripCommand == RIPv2.COMMAND_RESPONSE) {
			List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>(ripTable.values());
			rip.setEntries(entries);
		} else {
			rip.setEntries(new ArrayList<RIPv2Entry>());
		}

		udp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();

		return ether;
	}

	private void handleRipPacket(RIPv2 ripPacket, Iface inIface) {

		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			Ethernet ripPacketResponse = setupRipPacket(RIPv2.COMMAND_RESPONSE, inIface.getIpAddress(),
					inIface.getMacAddress());
			sendPacket(ripPacketResponse, inIface);
			return;
		}

		boolean updated = false;
		List<RIPv2Entry> newRipEntries = ripPacket.getEntries();
		for (RIPv2Entry entry : newRipEntries) {

			if (ripTable.containsKey(entry.getAddress())) {
				int currentMetric = ripTable.get(entry.getAddress()).getMetric();
				int newMetric = entry.getMetric() + 1;

				if (newMetric < currentMetric) {
					ripTable.remove(entry.getAddress());
					if (newMetric < 16) {
						updated = updateRipEntry(entry, inIface);
					}
				}
			} else {
				updated = updateRipEntry(entry, inIface);
			}
		}

		if (updated) {
			broadcastRIP(RIPv2.COMMAND_RESPONSE);
		}
	}

	private boolean updateRipEntry(RIPv2Entry entry, Iface inIface) {

		int metric = entry.getMetric() + 1;
		if (metric > 16) {
			metric = 16;
		}
		entry.setMetric(metric);
		ripTable.put(entry.getAddress(), entry);

		RouteEntry rEntry = routeTable.lookup(entry.getAddress());
		// update
		if (rEntry != null) {
			rEntry.setInterface(inIface);
			rEntry.setSubnetAddress(entry.getSubnetMask());
			rEntry.setGatewayAddress(entry.getNextHopAddress());
			ExpireRouteEntryTask task = rEntry.getTimerTask();
			if (task != null) {
				task.cancel();
				timer.purge();
				task = new ExpireRouteEntryTask(rEntry.getDestinationAddress(), rEntry.getMaskAddress());
				rEntry.resetTimerTask(task);
				timer.schedule(task, ROUTE_ENTRY_EXPIRATION_TIME);
			}
		} else {
			ExpireRouteEntryTask newTask = new ExpireRouteEntryTask(entry.getAddress(), entry.getSubnetMask());
			routeTable.insert((entry.getAddress() & entry.getSubnetMask()), inIface.getIpAddress(),
					inIface.getSubnetMask(), inIface, newTask);
			timer.schedule(newTask, ROUTE_ENTRY_EXPIRATION_TIME);
		}
		return true;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file " + routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file " + arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	public void sendICMP(Ethernet etherPacket, Iface inIface, byte type, byte code) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		// Nest packets inside the Ethernet packet
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		// Set Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4); // EtherType
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes()); // Source MAC
		int srcIp = ipPacket.getSourceAddress(); // Destination MAC - find and set
		RouteEntry routeEntry = this.routeTable.lookup(srcIp);
		int nextHop = routeEntry.getGatewayAddress();
		if (nextHop == 0)
			nextHop = srcIp;
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null) {
			ether.setDestinationMACAddress(etherPacket.getSourceMAC().toBytes());
		} else {
			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		}
		// Set IP header
		ip.setTtl((byte) 64); // TTL — set to 64
		ip.setProtocol(IPv4.PROTOCOL_ICMP); // Protocol
		if (code == ICMP_ECHO_REPLY_CODE && type == ICMP_ECHO_REPLY_TYPE) { // Source IP
			ip.setSourceAddress(ipPacket.getDestinationAddress());
		} else {
			ip.setSourceAddress(inIface.getIpAddress());
		}
		ip.setDestinationAddress(srcIp); // Destination IP
		// Set ICMP header
		icmp.setIcmpType(type); // Type
		icmp.setIcmpCode(code); // Code
		// Set Data
		if (code == ICMP_ECHO_REPLY_CODE && type == ICMP_ECHO_REPLY_TYPE) {
			ICMP icmpPacket = (ICMP) ipPacket.getPayload();
			data.setData(icmpPacket.getPayload().serialize());
		} else {
			int ipPacketHeaderLength = 4 * (int) ipPacket.getHeaderLength(); // header length in byte
			byte[] icmpData = new byte[4 + ipPacketHeaderLength + 8];
			ByteBuffer bb = ByteBuffer.wrap(icmpData);
			// 4 bytes of padding, all 0
			bb.putInt(0);
			// original IP header and 8 bytes following it, starting from the start of
			// packet byte arr
			bb.put(ipPacket.serialize(), 0, ipPacketHeaderLength + 8);
			data.setData(icmpData);
		}
		// Reset checksum from inside out
		icmp.resetChecksum();
		ip.resetChecksum();
		ether.resetChecksum();
		// Send packet
		sendPacket(ether, inIface);
	}

	// public void handlePacket(Ethernet etherPacket, Iface inIface)
	// {
	// 	System.out.println("*** -> Received packet: " +
    //             etherPacket.toString().replace("\n", "\n\t"));
		
	// 	/********************************************************************/
	// 	/* TODO: Handle packets                                             */
		
	// 	switch(etherPacket.getEtherType())
	// 	{
	// 	case Ethernet.TYPE_IPv4:
	// 		this.handleIpPacket(etherPacket, inIface);
	// 		break;

	// 	case Ethernet.TYPE_ARP:
	// 		this.handle_Arp_Packet(etherPacket, inIface);
	// 		break;
	// 	}

		
	// 	/********************************************************************/
	// }

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

		// drop packets that are not IPv4
		if (etherPacket.getEtherType() == Ethernet.TYPE_ARP ){
			handle_Arp_Packet(etherPacket, inIface);
			return;
		}	

		System.out.println("retain packet - ipv4");
		//verify checksum
		IPv4 packet = (IPv4) etherPacket.getPayload();
		short gtChecksum = packet.getChecksum();
		packet.resetChecksum(); // trigger checksum re-calculation in serialize()
		ByteBuffer packetByteBuffer = ByteBuffer.wrap(packet.serialize());
		short predChecksum = packetByteBuffer.getShort(10);
		if (gtChecksum != predChecksum)
			return;

		System.out.println("checksum correct - retain packet");
		// decrease and verify ttl
		int prevTtl = packet.getTtl(); // implicit conversion from byte to int
		int currTtl = prevTtl - 1;
		if (currTtl == 0) {
			sendICMP(etherPacket, inIface, ICMP_TIMEOUT_TYPE, ICMP_TIMEOUT_CODE);
			return;
		}
		packet.setTtl((byte) currTtl);

		System.out.println("ttl correct - retain packet");
		// update checksum (necessary as we updated ttl)
		packet.resetChecksum();

		//handle rip packet
		if((packet.getProtocol() == IPv4.PROTOCOL_UDP) && (packet.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9"))){
			UDP udpPacket = (UDP) packet.getPayload();
			if(udpPacket.getSourcePort() == UDP.RIP_PORT){
				RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
				handleRipPacket(ripPacket, inIface);
				return;
			}	
		}

		byte[] packetData = packet.serialize();
		packet.deserialize(packetData, 0, packetData.length);

		// if the packet is destined for one of router's interfaces, drop the packet
		int destIp = packet.getDestinationAddress();
		for (Iface iface : this.interfaces.values()) {
			int ifaceIp = iface.getIpAddress();
			if (destIp == ifaceIp) {
				byte protocol = packet.getProtocol();
				if (protocol == IPv4.PROTOCOL_UDP || protocol == IPv4.PROTOCOL_TCP) {
					sendICMP(etherPacket, inIface, ICMP_PORT_NOT_REACHABLE_TYPE, ICMP_PORT_NOT_REACHABLE_CODE);
				} else if (protocol == IPv4.PROTOCOL_ICMP) {
					ICMP icmp = (ICMP) packet.getPayload();
					if (icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
						sendICMP(etherPacket, inIface, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REPLY_CODE);
						System.out.println("ICMP response sent");
					}
				}
				System.out.println("packet is destined for router's interface - drop");
				return;
			}
		}
		System.out.println("forward packet");
		// else, forward the packet
		etherPacket.setPayload(packet);
		forward(etherPacket, inIface);
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
        { return; }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();

		//handle rip packet
		if((ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) && (ipPacket.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9"))){
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
        	{ return; }
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

	private void forward(Ethernet etherPacket, Iface inIface) {
		// find matching route table entry
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dst = ipPacket.getDestinationAddress();
		RouteEntry match = this.routeTable.lookup(dst);

		// if no entry matched, drop
		if (match == null) {
			sendICMP(etherPacket, inIface, ICMP_HOST_NOT_REACHABLE_TYPE, ICMP_HOST_NOT_REACHABLE_CODE);
			System.out.println("no match from routeTable - drop");
			return;
		}

		// out should not be the same as the source
		Iface outIface = match.getInterface();
		if (outIface == inIface) {
			System.out.println("out is the same as source - drop");
			return;
		}

		// determine next-hop IP address
		// first check gateway
		int nextHop = match.getGatewayAddress();
		if (nextHop == 0) {
			nextHop = dst;
		}

		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null) {
			// if no entry is found, generate a destination host unreachable ICMP message
			// and drop the packet
			sendICMP(etherPacket, inIface, ICMP_HOST_NOT_REACHABLE_TYPE, ICMP_HOST_NOT_REACHABLE_CODE);
			// enqueue the packet and generate an ARP request if no matching entry is found
			// in the ARP cache
			handleNoEntryMatch(etherPacket, inIface, ipPacket, match, nextHop);
			return;
		}

		// update Ethernet header & send packet
		System.out.println(outIface.getMacAddress() + "->" + arpEntry.getMac());
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		System.out.println("send packet");
		this.sendPacket(etherPacket, outIface);
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
        { return; }

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
        { return; }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

	

	public void handle_Arp_Packet(Ethernet etherPacket, Iface inIface) {
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		// if an ARP packet is an ARP request, generate ARP replies
		if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
			System.out.println("We have an ARP Request");
			int dstIP = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress()); // Destination IP
			MACAddress dstMAC = MACAddress.valueOf(arpPacket.getSenderHardwareAddress()); // Destination MAC address
			arpCache.insert(dstMAC, dstIP);
			// only respond to ARP requests whose target IP equals IP of interface on which
			// the ARP request was received.
			if (targetIp == inIface.getIpAddress()) {

				Ethernet ether = new Ethernet();
				ARP arp_Replies = new ARP();
				ether.setPayload(arp_Replies);

				// populate the fields in the Ethernet header
				ether.setEtherType(Ethernet.TYPE_ARP); // EtherType
				ether.setSourceMACAddress(inIface.getMacAddress().toBytes()); // Source MAC
				ether.setDestinationMACAddress(etherPacket.getSourceMACAddress()); // Destination MAC

				// populate the fields in the ARP Header
				arp_Replies.setHardwareType(ARP.HW_TYPE_ETHERNET); // Hardware type
				arp_Replies.setProtocolType(ARP.PROTO_TYPE_IP); // Protocol type
				arp_Replies.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH); // Hardware
																											// address
																											// length
				arp_Replies.setProtocolAddressLength((byte) 4); // Protocol address length
				arp_Replies.setOpCode(ARP.OP_REPLY); // Opcode
				arp_Replies.setSenderHardwareAddress(inIface.getMacAddress().toBytes()); // Sender hardware address
				arp_Replies.setSenderProtocolAddress(inIface.getIpAddress()); // Sender protocol address
				arp_Replies.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress()); // Target hardware address
				arp_Replies.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress()); // Target protocol address

				ether.resetChecksum();
				sendPacket(ether, inIface);
			}
		} else if (arpPacket.getOpCode() == ARP.OP_REPLY) { // Generate ARP requests

			int dstIP = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress()); // Destination IP
			MACAddress dstMAC = MACAddress.valueOf(arpPacket.getSenderHardwareAddress()); // Destination MAC address

			// insert arpCache entry for the corresponding ARP reply
			arpCache.insert(dstMAC, dstIP);

			// dequeue any waiting packets, fill in the correct destination MAC address
			UnknownQueue foundHost = Arp_map.get(dstIP);
			if (foundHost != null) {
				// cancel any pending arp timer tasks since we got the information we needed
				foundHost.getArpTask().cancel();
				// remove the scheduled tasks from the timer
				timer.purge();
				// send those packets out the interface on which the ARP reply arrived
				Queue<Ethernet> messages = foundHost.getMessages();
				for (Ethernet msg : messages) {
					System.out.println("Found the host! Send packets.");
					msg.setDestinationMACAddress(dstMAC.toBytes());
					// Find OutIface
					IPv4 ipPacket = (IPv4) msg.getPayload();
					int dstAddr = ipPacket.getDestinationAddress();
					// Find matching route table entry
					RouteEntry match = this.routeTable.lookup(dstAddr);
					// Send packet
					sendPacket(msg, match.getInterface());
				}
				Arp_map.remove(dstIP);
			}
		}
	}

	public Ethernet gen_Arp_Request(int nextHop, Iface outIface) {
		//byte[] broadcast = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
		byte[] empty = { 0, 0, 0, 0, 0, 0 };

		Ethernet ether = new Ethernet();
		ARP arp_Requests = new ARP();
		ether.setPayload(arp_Requests);

		// Populate the fields in the Ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(BROADCAST); // Set to the broadcast MAC address FF:FF:FF:FF:FF:FF

		// Set the fields for the ARP Header
		arp_Requests.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp_Requests.setProtocolType(ARP.PROTO_TYPE_IP);
		arp_Requests.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp_Requests.setProtocolAddressLength((byte) 4);
		arp_Requests.setOpCode(ARP.OP_REQUEST); // Set to ARP.OP_REQUEST
		arp_Requests.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
		arp_Requests.setSenderProtocolAddress(outIface.getIpAddress());
		arp_Requests.setTargetHardwareAddress(empty); // Set to 0
		arp_Requests.setTargetProtocolAddress(nextHop);

		ether.resetChecksum();

		return ether;
	}

	private void handleNoEntryMatch(Ethernet etherPacket, Iface inIface, IPv4 ipkt, RouteEntry match, int nextHop) {

		// if our map already has the destination address in it add message to queue
		if (Arp_map.containsKey(ipkt.getDestinationAddress())) {
			// need to add the message to our queue
			System.out.println("Adding new message to existing queue");
			UnknownQueue unknownHost = Arp_map.get(ipkt.getDestinationAddress());
			unknownHost.getMessages().add(etherPacket);
		}
		// generate ARP request and broadcast it on all non-incoming interfaces
		else {
			int timeBeforeResend = 1000; // 1 second
			Ethernet arpRequest = gen_Arp_Request(nextHop, inIface);

			/* Construct new object */
			ARPTask sendARPTask = new ARPTask(arpRequest, match.getInterface(), ipkt.getDestinationAddress());
			UnknownQueue unknownHostInfo = new UnknownQueue(etherPacket, sendARPTask);

			// get destination IP and add the corresponding UnknownQueue to the map
			Arp_map.put(ipkt.getDestinationAddress(), unknownHostInfo);

			// Schedule the task to go off in 1 second
			timer.schedule(sendARPTask, timeBeforeResend, timeBeforeResend);

			sendPacket(arpRequest, match.getInterface());
		}
	}

	class ARPTask extends TimerTask {
		private Ethernet ether;
		private Iface inIface;
		private int dstIP;

		public ARPTask(Ethernet ePacket, Iface i, int ip) {
			ether = ePacket;
			dstIP = ip;
			inIface = i;
		}

		@Override
		public void run() {
			System.out.println("Resend ARP Request");
			checkArpRequestTimes(ether, inIface, dstIP);
		}
	}

	private void checkArpRequestTimes(Ethernet arp_Requests, Iface outIface, int dstIP) {
		UnknownQueue unknownHost = Arp_map.get(dstIP);
		// Send the message up to 3 times
		if (unknownHost.getSentTime() < 3) {
			unknownHost.incSentTime();
			sendPacket(arp_Requests, outIface);
		}
		// If it has already been sent 3 times, don't reschedule the timer
		else {
			IPv4 ipPacket;
			// cancel timertask
			unknownHost.getArpTask().cancel();
			// purge timer
			timer.purge();
			Queue<Ethernet> messages = unknownHost.getMessages();
			System.out.println("size of queue" + messages.size());
			// Ethernet msg;
			for (Ethernet msg : messages) {
				// Find InIface
				ipPacket = (IPv4) msg.getPayload();
				int dstAddr = ipPacket.getSourceAddress();
				// Find matching route table entry
				RouteEntry match = this.routeTable.lookup(dstAddr);
				sendICMP(msg, match.getInterface(), ICMP_HOST_NOT_REACHABLE_TYPE, ICMP_HOST_NOT_REACHABLE_CODE);
			}

			// remove dstIP from map
			Arp_map.remove(unknownHost);
		}
	}

	class ExpireRouteEntryTask extends TimerTask {
		private int dst, mask;

		public ExpireRouteEntryTask(int dst, int mask) {
			this.dst = dst;
			this.mask = mask;
		}

		@Override
		public void run() {
			ripTable.remove(dst);
			routeTable.remove((dst & mask), mask);
		}
	}

	class RipBroadcastTask extends TimerTask {
		private Router router;

		public RipBroadcastTask(Router r) {
			router = r;
		}

		@Override
		public void run() {
			router.broadcastRIP(RIPv2.COMMAND_RESPONSE);
		}
	}

	public class UnknownQueue {
		private Queue<Ethernet> messages;
		private int sent_time;
		private ARPTask arp_task;

		public UnknownQueue(Ethernet packet, ARPTask task) {
			messages = new LinkedList<Ethernet>();
			messages.add(packet);
			sent_time = 0;
			arp_task = task;
		}

		public int getSentTime() {
			return sent_time;
		}

		public void incSentTime() {
			sent_time++;
		}

		public Queue<Ethernet> getMessages() {
			return messages;
		}

		public ARPTask getArpTask() {
			return arp_task;
		}
	}

}
