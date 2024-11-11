package aces.webctrl.wireshark.core;
import java.util.*;
import com.controlj.green.commbase.api.*;
import com.controlj.green.core.data.*;
/**
 * Utility class meant to facilitate access to WebCTRL's internal database API.
 */
public class DatabaseLink implements AutoCloseable {
  /** Controls the connection to the underlying database. */
  public volatile CoreDataSession cds;
  /** Used to cache CoreNodes. */
  private volatile HashMap<String,CoreNode> nodeMap = new HashMap<String,CoreNode>();
  /** Specifies whether modifications can be made to the underlying database. */
  private volatile boolean readOnly;
  /** Specifies whether to automatically commit changes. */
  private volatile boolean autoCommit;
  /** Objects to automatically close when this {@code DatabaseLink} is closed. */
  private final ArrayList<AutoCloseable> res = new ArrayList<AutoCloseable>();
  /**
   * Opens a new CoreDataSession.
   * @param readOnly specifies whether to expect any modifications to the underlying operator database.
   */
  public DatabaseLink(boolean readOnly) throws CoreDatabaseException {
    this.readOnly = readOnly;
    this.autoCommit = !readOnly;
    cds = CoreDataSession.open(readOnly?0:1);
  }
  /**
   * Any added resource will be closed when this {@code DatabaseLink} is closed.
   */
  public void addResource(AutoCloseable ac){
    res.add(ac);
  }
  /**
   * @param autoCommit specifies whether to automatically commit changes.
   */
  public void setAutoCommit(boolean autoCommit){
    this.autoCommit = autoCommit;
  }
  /**
   * @return whether to automatically commit changes.
   */
  public boolean isAutoCommit(){
    return autoCommit;
  }
  /**
   * @return whether the underlying database connection is read-only.
   */
  public boolean isReadOnly(){
    return readOnly;
  }
  /**
   * @return a list of BACnet/IP connection details for the server.
   */
  public ArrayList<ConnectionParams> getConnectionDetails() throws CoreIntegrityException {
    final ArrayList<ConnectionParams> connections = new ArrayList<ConnectionParams>(4);
    ConnectionParams cp = new ConnectionParams();
    int x;
    for (CoreNode a: getNode("/trees/config/connections").getChildrenByType((short)4)){
      x = 0;
      for (CoreNode b: a.getChildren()){
        switch (b.getReferenceName()){
          case "ip_address":{
            cp.ipAddress = b.getValueString();
            ++x;
            break;
          }
          case "subnetmask":{
            cp.subnetMask = b.getValueString();
            ++x;
            break;
          }
          case "port":{
            try{
              cp.port = Integer.parseInt(b.getValueString());
            }catch(NumberFormatException e){
              cp.port = 47808;
            }
            ++x;
            break;
          }
          case "foreign_device":{
            cp.fdr = "force".equals(b.getValueString());
            ++x;
            break;
          }
          case "register_with_device":{
            cp.primary = b.getValueString();
            ++x;
            break;
          }
          case "register_with_alt_device":{
            cp.secondary = b.getValueString();
            ++x;
            break;
          }
        }
        if (x==6){
          cp.ipAddressBits = Utility.getAddressBits(cp.ipAddress);
          cp.subnetMaskBits = Utility.getAddressBits(cp.subnetMask);
          if (cp.ipAddressBits==0){
            cp.ipAddress = "0.0.0.0";
          }
          if (cp.subnetMaskBits==0){
            cp.subnetMask = "0.0.0.0";
          }
          cp.dbid = a.getDbid();
          cp.name = a.getDisplayName();
          connections.add(cp);
          cp = new ConnectionParams();
          break;
        }
      }
    }
    return connections;
  }
  /**
   * @return a mapping of IP devices on the network tree keyed by IPv4 address.
   */
  public TreeMap<Integer,Router> getRouters() throws CoreIntegrityException {
    final TreeMap<Integer,Router> map = new TreeMap<Integer,Router>(Router.UNSIGNED);
    final String proto = MediaType.BACNET_IP.toString();
    Router r;
    for (CoreNode a: getNode("/trees/network").getChildrenByType((short)105)){
      if (!"discovered".equals(a.getReferenceName())){
        for (CoreNode b: a.getChildrenByType((short)202)){
          if (proto.equals(b.getAttribute(CoreNodeConstants.MEDIA_TYPE))){
            for (CoreNode c: b.getChildrenByCategory(NodeType.CAT_HW_DEVICE)){
              if (c instanceof CoreHWDevice){
                r = new Router(this, (CoreHWDevice)c);
                map.put(r.ipAddressBits, r);
                if (Initializer.isKilled()){ return map; }
              }
            }
          }
        }
      }
    }
    return map;
  }
  /**
   * @return the CoreNode corresponding to the given absolute path.
   */
  public CoreNode getNode(String path) throws CoreIntegrityException {
    CoreNode n = nodeMap.get(path);
    if (n==null){
      n = cds.getExpectedNode(path);
      nodeMap.put(path,n);
    }
    return n;
  }
  /**
   * @return the CoreNode corresponding to the given DBID.
   */
  public CoreNode getNode(long dbid) throws CoreNotFoundException {
    return cds.getNode(dbid);
  }
  /**
   * Commits changes to the underlying database.
   */
  public void commit(){
    cds.commit();
  }
  /**
   * Closes the CoreDataSession associated with this Object.
   */
  @Override public void close(){
    try{
      for (AutoCloseable ac: res){
        ac.close();
      }
    }catch(Exception e){
      Initializer.log(e);
    }
    if (autoCommit){
      commit();
    }
    cds.close();
    res.clear();
  }
}