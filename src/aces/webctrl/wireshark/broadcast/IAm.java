package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
/**
 * An I-Am packet is usually sent in response to a Who-Is packet.
 * The Who-Is packet specifies a range of device instance numbers.
 * Any device belonging in the range should respond with an I-Am packet.
 * After address binding occurs through this process, information can be transmitted unicast.
 */
public class IAm extends Broadcast {
  /** The instance number of the device identified by this I-Am packet. */
  public volatile int instance;
  /** The vendor number of the device identified by this I-Am packet. */
  public volatile int vendor;
  /**
   * Create a new I-Am packet.
   */
  public IAm(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int instance, int vendor){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.instance = instance;
    this.vendor = vendor;
  }
  /**
   * @return the name of the vendor of the device identified by this I-Am packet.
   */
  public String getVendor(){
    return Constants.getVendor(vendor);
  }
  /**
   * @return the instance and vendors numbers (comma-delimited) of the device identified by this I-Am packet.
   */
  @Override public String getData(){
    return instance+","+getVendor();
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.iAm;
  }
}