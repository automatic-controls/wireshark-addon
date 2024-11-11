package aces.webctrl.wireshark.broadcast;
/**
 * This class is used an as initial filter for selecting only broadcast packets relevant to the WebCTRL server.
 */
public class PacketFilter {
  /** Specifies the name of the BACnet/IP connection and whether the packet was transmitted with FDR. */
  public volatile String category;
  /** A whitelisted source IPv4 address. */
  public volatile int srcIP;
  /** A whitelisted destination IPv4 address. */
  public volatile int dstIP;
  /** A whitelisted destination port */
  public volatile int dstPort;
  /** 
   * Create a new PacketFilter.
   * Integer parameters can be specified as {@code -1} to indicate all inputs are accepted.
   */
  public PacketFilter(String category, int srcIP, int dstIP, int dstPort){
    this.category = category;
    this.srcIP = srcIP;
    this.dstIP = dstIP;
    this.dstPort = dstPort;
  }
  /**
   * @return whether a packet with the given source IP, destination IP, and destination port is accepted by this filter.
   */
  public boolean accept(int srcIP, int dstIP, int dstPort){
    if (this.dstPort!=-1 && this.dstPort!=dstPort){
      return false;
    }
    if (this.dstIP!=-1 && this.dstIP!=dstIP){
      return false;
    }
    if (this.srcIP!=-1 && this.srcIP!=srcIP){
      return false;
    }
    return true;
  }
}