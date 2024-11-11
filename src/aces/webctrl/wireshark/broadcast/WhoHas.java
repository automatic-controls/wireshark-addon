package aces.webctrl.wireshark.broadcast;
import aces.webctrl.wireshark.core.*;
/**
 * An I-Have packet is usually sent in response to a Who-Has packet.
 * This mechanism is used to identify devices containing specific BACnet objects in their local databases.
 */
public class WhoHas extends Broadcast {
  /** The minimum accepted instance number of devices to search. */
  public volatile int low;
  /** The maximum accepted instance number of devices to search. */
  public volatile int high;
  /** The type number of the BACnet object which is sought. */
  public volatile int objectType;
  /** The number of the BACnet object which is sought. */
  public volatile int objectNumber;
  /** The name of the BACnet object which is sought. */
  public volatile String objectName;
  /**
   * Create a new Who-Has packet.
   */
  public WhoHas(String category, long time, int srcIP, int srcPort, int srcNetwork, int srcAddress, int service, int low, int high, int objectType, int objectNumber, String objectName){
    super(category, time, srcIP, srcPort, srcNetwork, srcAddress, service);
    this.low = low;
    this.high = high;
    this.objectType = objectType;
    this.objectNumber = objectNumber;
    this.objectName = objectName.intern();
  }
  /**
   * @return whether the given I-Have packet could have been in response to this Who-Has packet.
   */
  public boolean matches(IHave p){
    if (low!=4194303 && p.instance!=-1 && (p.instance<low || p.instance>high)){
      return false;
    }
    if (objectType!=-1 && p.objectType!=-1 && objectType!=p.objectType){
      return false;
    }
    if (objectNumber!=-1 && p.objectNumber!=-1 && objectNumber!=p.objectNumber){
      return false;
    }
    if (objectName!=null && p.name!=null && !objectName.isEmpty() && !p.name.isEmpty() && !objectName.equals(p.name)){
      return false;
    }
    return true;
  }
  /**
   * @return a display-friendly name for the object type being sought.
   */
  public String getObjectType(){
    return Constants.getObjectType(objectType);
  }
  /**
   * @return details related to the BACnet object being sought.
   */
  @Override public String getData(){
    boolean first = true;
    final StringBuilder sb = new StringBuilder(32);
    if (low!=4194303 && high!=4194303){
      if (first){
        first = false;
      }else{
        sb.append(',');
      }
      if (low==high){
        sb.append(low);
      }else{
        sb.append("["+low+","+high+"]");
      }
    }
    if (objectType!=-1){
      if (first){
        first = false;
      }else{
        sb.append(',');
      }
      sb.append(getObjectType()+":"+objectNumber);
    }
    if (!objectName.isEmpty()){
      if (first){
        first = false;
      }else{
        sb.append(',');
      }
      sb.append(objectName);
    }
    return sb.toString();
  }
  /**
   * {@inheritDoc}
   */
  @Override public void incrementStats(StatPoint sp){
    ++sp.whoHas;
  }
  /**
   * @return an unique identifier for the object filter specified by this packet.
   */
  public GUID getGUID(){
    return new GUID(low, high, objectType, objectNumber);
  }
  public static class GUID {
    private volatile int devLow;
    private volatile int devHigh;
    private volatile int object;
    private volatile int hash;
    public GUID(int low, int high, int objectType, int objectNumber){
      devLow = low;
      devHigh = high;
      object = (objectType<<22)|objectNumber;
      hash = ((31+object)*31+devLow)*31+devHigh;
    }
    @Override public String toString(){
      return Utility.pad(Integer.toHexString(devLow), "0", 6)+Utility.pad(Integer.toHexString(devHigh), "0", 6)+Utility.pad(Integer.toHexString(object), "0", 8);
    }
    @Override public boolean equals(Object obj){
      if (this==obj){
        return true;
      }else if (obj instanceof GUID){
        final GUID x = (GUID)obj;
        return hash==x.hash && devLow==x.devLow && devHigh==x.devHigh && object==x.object;
      }else{
        return false;
      }
    }
    @Override public int hashCode(){
      return hash;
    }
  }
}