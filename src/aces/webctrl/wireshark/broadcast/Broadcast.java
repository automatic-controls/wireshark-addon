package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.*;
/**
 * This is a base class encapsulating the information contained in a single broadcast packet.
 * Many sub-classes extend this class to include more information.
 * The natural sort-order is descending by timestamp.
 */
public class Broadcast implements Comparable<Broadcast> {
  /** Specifies the name of the BACnet/IP connection and whether the packet was transmitted with FDR. */
  public volatile String category;
  /** Spceifies this packet's timestamp in epoch milliseconds. */
  public volatile long time;
  /** The source IP address of the packet. */
  public volatile int srcIP;
  /** The source port of the packet. */
  public volatile int srcPort;
  /** The source network number of the packet. */
  public volatile int srcNetwork;
  /** The source MAC address of the packet. */
  public volatile int srcAddress;
  /** The service number attached to the packet. */
  public volatile int service;
  /** Create a new Broadcast. */
  public Broadcast(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service){
    this.category = category.intern();
    this.time = time;
    this.srcIP = srcIP;
    this.srcPort = srcPort;
    this.srcNetwork = srcNetwork;
    this.srcAddress = srcAddress;
    this.service = service;
  }
  /**
   * Create an empty Broadcast for the purpose of performing a binary search.
   */
  public Broadcast(long time){
    this.time = time;
  }
  /**
   * Increment the counter corresponding to this packet.
   * Subclasses override this method to use different counters.
   */
  public void incrementStats(StatPoint sp){
    ++sp.other;
  }
  /**
   * Subclasses override this method to provide additional information about the packet.
   */
  public String getData(){
    return "";
  }
  /**
   * Provides a System.out.println friendly summary String primary used for debugging purposes.
   */
  @Override public String toString(){
    return getTime()+','+category+','+getSourceIP()+':'+srcPort+','+getSourceNetwork()+','+getSourceMAC()+','+getService()+','+getData();
  }
  /**
   * Appends information about this packet as a JSON object to the given StringBuilder.
   */
  public void toJSON(StringBuilder sb){
    sb.append('{');
    sb.append("\"time\":").append(time).append(",\n");
    sb.append("\"category\":\"").append(Utility.escapeJSON(category)).append("\",\n");
    sb.append("\"sourceIP\":\"").append(getSourceIP()+':'+srcPort).append("\",\n");
    sb.append("\"sourceNetwork\":\"").append(getSourceNetwork()).append("\",\n");
    sb.append("\"sourceMAC\":\"").append(getSourceMAC()).append("\",\n");
    sb.append("\"service\":\"").append(getService()).append("\",\n");
    sb.append("\"data\":\"").append(Utility.escapeJSON(getData())).append("\",\n");
    sb.append('}');
  }
  /**
   * @return a formatted String for the timestamp of this packet.
   */
  public String getTime(){
    return Utility.format(time);
  }
  /**
   * @return a String containing the source IPv4 address of this packet.
   */
  public String getSourceIP(){
    return Utility.getIPv4(srcIP);
  }
  /**
   * @return a unique identifier for the packet's source information.
   */
  public String getSourceID(){
    return Utility.pad(Integer.toHexString(srcIP), "0", 8)+
      Utility.pad(Integer.toHexString(srcNetwork&0xFFFF), "0", 4)+
      (srcAddress==-1?"":Integer.toHexString(srcAddress));
  }
  /**
   * @return the source network number of this packet, or {@code "N/A"} if no source network was specified.
   */
  public String getSourceNetwork(){
    if (srcNetwork==-1){
      return "N/A";
    }else{
      return String.valueOf(srcNetwork);
    }
  }
  /**
   * @return the source MAC address of this packet, or {@code "N/A"} if no source MAC was specified.
   *         In some cases, the source MAC address may return an IPv4 address.
   */
  public String getSourceMAC(){
    if (srcAddress==-1){
      return "N/A";
    }else if (srcAddress>=0 && srcAddress<256){
      return String.valueOf(srcAddress);
    }else if ((srcAddress&0xFF000000)!=0){
      return Utility.getIPv4(srcAddress);
    }else{
      return "N/A";
    }
  }
  /**
   * @return a user-friendly String which names the service associated to this packet, or {@code "UNKNOWN"} if the service is unrecognized.
   */
  public String getService(){
    return Constants.getService(service);
  }
  /**
   * Specifies a natural sort-order that is descending by timestamp.
   */
  @Override public int compareTo(Broadcast x){
    if (time==x.time){
      return 0;
    }
    return time<x.time?1:-1;
  }
}