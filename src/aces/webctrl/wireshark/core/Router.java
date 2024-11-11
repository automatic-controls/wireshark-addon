package aces.webctrl.wireshark.core;
import java.util.*;
import com.controlj.green.core.data.*;
/**
 * Represents a single BACnet/IP router on the network tree.
 */
public class Router implements AutoCloseable {
  /** Enforces an ascending, unsigned integer sort. */
  public final static Comparator<Integer> UNSIGNED = new Comparator<Integer>(){
    @Override public int compare(Integer x, Integer y){
      return Integer.compareUnsigned(x, y);
    }
  };
  /** A reference to the DatabaseLink corresponding to this object. */
  private volatile DatabaseLink dl;
  /** A reference to the database node corresponding to this router. */
  public volatile CoreHWDevice node;
  /** A unique identifier of this router node in the WebCTRL database. */
  private volatile long dbid;
  /** The display name of this router. */
  public volatile String displayName;
  /** The reference name of this router. */
  public volatile String referenceName;
  /** The model name of this router, or {@code null} if the router was not manufactured by ALC. */
  public volatile String modelName;
  /** The IPv4 address of this router. */
  public volatile String ipAddress;
  /** The subnet mask of this router. */
  public volatile String subnetMask;
  /** The default gateway of this router. */
  public volatile String defaultGateway;
  /** The IPv4 address of this router. */
  public volatile int ipAddressBits;
  /** The subnet mask of this router. */
  public volatile int subnetMaskBits;
  /** The default gateway of this router. */
  public volatile int defaultGatewayBits;
  /**
   * Create a new Router details object.
   */
  public Router(DatabaseLink dl, CoreHWDevice node){
    this.dl = dl;
    this.node = node;
    readParams();
    dl.addResource(this);
  }
  /**
   * Load this router's details into RAM.
   */
  public void readParams(){
    referenceName = node.getReferenceName();
    ipAddress = node.getMacAddress();
    ipAddressBits = Utility.getAddressBits(ipAddress);
    modelName = node.getAttribute(CoreNodeConstants.MODEL_NAME);
    displayName = node.getDisplayName();
    dbid = node.getDbid();
    if (displayName==null){
      displayName = referenceName;
    }
    defaultGateway = node.getAttribute(CoreNodeConstants.DEFAULT_GATEWAY);
    subnetMask = node.getAttribute(CoreNodeConstants.SUBNET_MASK);
    defaultGatewayBits = Utility.getAddressBits(defaultGateway);
    subnetMaskBits = Utility.getAddressBits(subnetMask);
    if (defaultGatewayBits==0){
      defaultGateway = "0.0.0.0";
    }
    if (subnetMaskBits==0){
      subnetMask = "0.0.0.0";
    }
  }
  /**
   * Uses the previously recorded DBID to retrieve a node object from the WebCTRL database corresponding to this router.
   */
  public boolean open(DatabaseLink dl) throws CoreNotFoundException {
    CoreNode n = dl.getNode(dbid);
    if (n instanceof CoreHWDevice){
      node = (CoreHWDevice)n;
      this.dl = dl;
      dl.addResource(this);
      return true;
    }else{
      return false;
    }
  }
  /**
   * @return the DBID of the this router's CoreNode
   */
  public long getDBID(){
    return dbid;
  }
  /**
   * @return whether the database node object is currently valid and ready for operations.
   */
  public boolean isOpen(){
    return dl!=null;
  }
  /**
   * Release resources associated to the WebCTRL node object.
   */
  @Override public void close(){
    dl = null;
    node = null;
  }
  /**
   * Pretty-print the details of this router to the given StringBuilder as a JSON object.
   */
  public void toJSON(StringBuilder sb, String indent){
    sb.append(indent).append("{\n");
    sb.append(indent).append("  \"dbid\": ").append(dbid).append(",\n");
    sb.append(indent).append("  \"referenceName\": \"").append(Utility.escapeJSON(referenceName)).append("\",\n");
    sb.append(indent).append("  \"displayName\": \"").append(Utility.escapeJSON(displayName)).append("\",\n");
    sb.append(indent).append("  \"modelName\": \"").append(Utility.escapeJSON(Utility.coalesce(modelName,"Unknown"))).append("\",\n");
    sb.append(indent).append("  \"ipAddress\": \"").append(ipAddress).append("\",\n");
    sb.append(indent).append("  \"subnetMask\": \"").append(subnetMask).append("\",\n");
    sb.append(indent).append("  \"defaultGateway\": \"").append(defaultGateway).append("\"\n");
    sb.append(indent).append('}');
  }
}