package aces.webctrl.wireshark.core;
import aces.webctrl.wireshark.broadcast.*;
import java.util.*;
/**
 * Encapsulates the data corresponding to a single BACnet/IP connection.
 */
public class ConnectionParams {
  /** The DBID of the connection node in the WebCTRL database. */
  public volatile long dbid;
  /** The name given to this connection. */
  public volatile String name;
  /** The IPv4 address of the WebCTRL server according to this connection. */
  public volatile String ipAddress;
  /** The subnet mask of the WebCTRL server according to this connection. */
  public volatile String subnetMask;
  /** The IPv4 address of the WebCTRL server according to this connection. */
  public volatile int ipAddressBits;
  /** The subnet mask of the WebCTRL server according to this connection. */
  public volatile int subnetMaskBits;
  /** The UDP port to route BACnet traffic through for this connection. */
  public volatile int port;
  /** Whether this connection utilizes foreign device registration (FDR) for the WebCTRL server. */
  public volatile boolean fdr;
  /** The reference name of the primary FDR router. */
  public volatile String primary;
  /** The reference name of the secondary FDR router. */
  public volatile String secondary;
  /** The primary FDR router. */
  public volatile Router primaryRouter = null;
  /** The secondary FDR router. */
  public volatile Router secondaryRouter = null;
  /**
   * Resolves the references names of FDR routers to known Router objects.
   */
  public void resolve(TreeMap<Integer,Router> routers){
    primaryRouter = null;
    secondaryRouter = null;
    final boolean a = primary==null || primary.isBlank();
    if (a){
      return;
    }
    final boolean b = secondary==null || secondary.isBlank();
    int x = b?1:2;
    for (Router r: routers.values()){
      if (r.referenceName.equals(primary)){
        primaryRouter = r;
        if (--x==0){
          return;
        }
      }else if (!b && r.referenceName.equals(secondary)){
        secondaryRouter = r;
        if (--x==0){
          return;
        }
      }
    }
  }
  /**
   * Adds packet filters for this connection to the given filter list.
   */
  public void addFilters(final List<PacketFilter> filters){
    filters.add(new PacketFilter(Utility.coalesce(name, "BACnet/IP")+" - LAN", -1, ipAddressBits|(~subnetMaskBits), port));
    if (fdr){
      if (primaryRouter==null){
        filters.add(new PacketFilter(Utility.coalesce(name, "BACnet/IP")+" - FDR", -1, ipAddressBits, port));
      }else{
        filters.add(new PacketFilter(Utility.coalesce(name, "BACnet/IP")+" - FDR", primaryRouter.ipAddressBits, ipAddressBits, port));
        if (secondaryRouter!=null){
          filters.add(new PacketFilter(Utility.coalesce(name, "BACnet/IP")+" - FDR", secondaryRouter.ipAddressBits, ipAddressBits, port));
        }
      }
    }
  }
  /**
   * Pretty-print this object's information into JSON format.
   */
  public void toJSON(StringBuilder sb, String indent){
    sb.append(indent).append("{\n");
    sb.append(indent).append("  \"dbid\": ").append(dbid).append(",\n");
    sb.append(indent).append("  \"name\": \"").append(Utility.escapeJSON(name)).append("\",\n");
    sb.append(indent).append("  \"ipAddress\": \"").append(ipAddress).append("\",\n");
    sb.append(indent).append("  \"subnetMask\": \"").append(subnetMask).append("\",\n");
    sb.append(indent).append("  \"port\": ").append(port).append(",\n");
    sb.append(indent).append("  \"fdr\": ").append(fdr).append(",\n");
    sb.append(indent).append("  \"primary\": \"").append(Utility.escapeJSON(primary)).append("\",\n");
    sb.append(indent).append("  \"secondary\": \"").append(Utility.escapeJSON(secondary)).append("\"\n");
    sb.append(indent).append('}');
  }
}