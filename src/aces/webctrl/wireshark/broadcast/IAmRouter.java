package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
import java.util.Arrays;
/**
 * An I-Am-Router packet is usually sent in response to a Who-Is-Router packet.
 * This mechanism is used to identify which routers manage specific network numbers.
 */
public class IAmRouter extends Broadcast {
  /** The device from which this packet originates is claiming to be the router used to access all of the network numbers listed here. */
  public volatile int[] networks;
  /**
   * Create a new I-Am-Router packet.
   */
  public IAmRouter(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int[] networks){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.networks = networks;
    Arrays.sort(this.networks);
  }
  /**
   * @return whether this I-Am-Router packet refers to the given network number.
   */
  public boolean hasNetwork(int network){
    return Arrays.binarySearch(this.networks, network)>=0;
  }
  /**
   * @return a comma-delimited list of network numbers that this I-Am-Router packet corresponds to.
   */
  @Override public String getData(){
    final StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (int i=0;i<networks.length;++i){
      if (first){
        first = false;
      }else{
        sb.append(',');
      }
      sb.append(networks[i]);
    }
    return sb.toString();
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.iAmRouter;
  }
}