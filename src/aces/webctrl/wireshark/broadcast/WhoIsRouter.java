package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
/**
 * An I-Am-Router packet is usually sent in response to a Who-Is-Router packet.
 * This mechanism is used to identify which routers manage specific network numbers.
 */
public class WhoIsRouter extends Broadcast {
  /** The network number being sought, or {@code -1} for a global request. */
  public volatile int network;
  /**
   * Create a new Who-Is-Router packet.
   * Set the network to {@code -1} to specify a global request.
   */
  public WhoIsRouter(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int network){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.network = network;
  }
  /**
   * @return whether this request is to be interpreted globally.
   */
  public boolean isGlobal(){
    return network==-1;
  }
  /**
   * @return the network number being sought, or the empty string when this packet is global.
   */
  @Override public String getData(){
    return network==-1?"":String.valueOf(network);
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.whoIsRouter;
  }
}