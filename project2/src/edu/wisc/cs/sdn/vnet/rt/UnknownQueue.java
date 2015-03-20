package edu.wisc.cs.sdn.vnet.rt;

import java.util.LinkedList;
import java.util.Queue;

import edu.wisc.cs.sdn.vnet.rt.Router.ARPTask;
import net.floodlightcontroller.packet.Ethernet;

public class UnknownQueue {
	private Queue<Ethernet> messages;
	private int timesSent;
	private ARPTask arpTask;
	
	public UnknownQueue(Ethernet packet, ARPTask task){
		messages = new LinkedList<Ethernet>();
		messages.add(packet);
		timesSent = 0;
		arpTask = task;
	}
	
	public int getTimesSent(){
		return timesSent;
	}
	
	public void incrementTimesSent(){
		timesSent++;
	}
	
	public Queue<Ethernet> getQueue(){
		return messages;
	}
	
	public ARPTask getArpTask(){
		return arpTask;
	}
	
}
