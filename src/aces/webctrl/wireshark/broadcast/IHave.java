package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.StatPoint;
/**
 * An I-Have packet is usually sent in response to a Who-Has packet.
 * This mechanism is used to identify devices containing specific BACnet objects in their local databases.
 */
public class IHave extends Broadcast {
  /** The device instance number of the BACnet object referenced by this packet. */
  public volatile int instance;
  /** The type number of the BACnet object referenced by this packet. */
  public volatile int objectType;
  /** The number of the BACnet object referenced by this packet. */
  public volatile int objectNumber;
  /** The name of the BACnet object referenced by this packet. */
  public volatile String name;
  /**
   * Create a new I-Have packet.
   */
  public IHave(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int instance, int objectType, int objectNumber, String name){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.instance = instance;
    this.objectType = objectType;
    this.objectNumber = objectNumber;
    this.name = name.intern();
  }
  /**
   * @return an identifier for the BACnet object which should be unique throughout the WebCTRL system.
   */
  public long getGUID(){
    return (((long)instance)<<32)|(((long)objectType)<<22)|((long)objectNumber);
  }
  /**
   * @return a display-friendly object type String.
   */
  public String getObjectType(){
    return Constants.getObjectType(objectType);
  }
  /**
   * @return details about the object this packet identifies.
   */
  @Override public String getData(){
    return "device:"+instance+","+getObjectType()+":"+objectNumber+(name.isEmpty()?"":","+name);
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.iHave;
  }
}