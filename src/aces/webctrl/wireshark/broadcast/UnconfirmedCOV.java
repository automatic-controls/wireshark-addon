package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
/**
 * Unconfirmed-COV packets are used to tell everyone that a particular value has changed.
 * For example, mapped network points rely on these sorts of notifications.
 * In most cases, COV can be communicated unicast, but occasionally broadcasts such as these are required.
 */
public class UnconfirmedCOV extends Broadcast {
  /** The device instance number corresponding to the changed value. */
  public volatile int instance;
  /** The object type number corresponding to the changed value. */
  public volatile int objectType;
  /** The object number corresponding to the changed value. */
  public volatile int objectNumber;
  /** 
   * Create a new Unconfirmed-COV packet.
   */
  public UnconfirmedCOV(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int instance, int objectType, int objectNumber){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.instance = instance;
    this.objectType = objectType;
    this.objectNumber = objectNumber;
  }
  /**
   * @return an identifier for the BACnet object which should be unique throughout the WebCTRL system.
   */
  public long getGUID(){
    return (((long)instance)<<32)|(((long)objectType)<<22)|((long)objectNumber);
  }
  /**
   * @return a display-friendly name for the object type corresponding to the changed value.
   */
  public String getObjectType(){
    return Constants.getObjectType(objectType);
  }
  /**
   * @return details about the value which has changed.
   */
  @Override public String getData(){
    return "device:"+instance+","+getObjectType()+":"+objectNumber;
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.unconfirmedCOV;
  }
}