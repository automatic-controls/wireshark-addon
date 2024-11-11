package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
/**
 * An I-Am packet is usually sent in response to a Who-Is packet.
 * The Who-Is packet specifies a range of device instance numbers.
 * Any device belonging in the range should respond with an I-Am packet.
 * After address binding occurs through this process, information can be transmitted unicast.
 */
public class WhoIs extends Broadcast {
  /** The minimum device instance number accepted. */
  public volatile int low;
  /** The maximum device instance number accepted. */
  public volatile int high;
  /**
   * Create a new WhoIs packet.
   * If both the low and high device instance limits are set to {@code 4194303},
   * then this Who-Is packet is to be globally accepted.
   */
  public WhoIs(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int low, int high){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    if (low==0 && high>=4194302){
      low = 4194303;
      high = 4194303;
    }
    this.low = low;
    this.high = high;
  }
  /**
   * @return whether this Who-Is packet matches the given instance number.
   */
  public boolean matches(int instance){
    return low==4194303 || instance>=low && instance<=high;
  }
  /**
   * @return whether this is a global Who-Is packet.
   */
  public boolean isGlobal(){
    return low==4194303;
  }
  /**
   * @return whether the specified instance number is contained in the range of this packet.
   */
  public boolean contains(int instance){
    return low==4194303 || instance>=low && instance<=high;
  }
  /**
   * @return the range of accepted device instance numbers formatted in a display-friendly manner.
   */
  @Override public String getData(){
    if (low==4194303){
      return "";
    }else if (low==high){
      return String.valueOf(low);
    }else{
      return "["+low+","+high+"]";
    }
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.whoIs;
  }
}