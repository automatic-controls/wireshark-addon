package aces.webctrl.wireshark.core;
import aces.webctrl.wireshark.broadcast.*;
import java.io.*;
import java.nio.file.*;
import io.pkts.*;
import io.pkts.packet.*;
import java.util.*;
/**
 * This class handles parsing PCAP files and loading the parsed data into RAM for further analysis.
 */
public class PacketCapture {
  /** The maximum number of packets to cache at any time. */
  private final static int CACHE_LIMIT = 1048576;
  /** A list of packets parsed from input PCAP files. */
  public final ArrayList<Broadcast> packets = new ArrayList<Broadcast>(32768);
  /** The timestamp of the first chronological packet to be parsed. */
  public volatile long start = -1;
  /** The timestamp of the last chronological packet to be parsed. */
  public volatile long end = -1;
  /**
   * Sorts the packet list by timestamp descending.
   */
  public void sortByTimeDesc(){
    packets.sort(null);
  }
  /**
   * Sorts the packet list by BACnet service type.
   */
  public void sortByService(){
    packets.sort(new Comparator<Broadcast>(){
      @Override public int compare(Broadcast x, Broadcast y){
        return (x.service&0xFF)-(y.service&0xFF);
      }
    });
  }
  /**
   * Loads the specified PCAP file into RAM.
   * The given filter list is used to select only those packets which are relevant.
   * Only packets with timestamp later than afterMillis are accepted.
   */
  public void load(Path pcapFile, final List<PacketFilter> filters, final long afterMillis){
    Pcap p = null;
    try(
      InputStream in = Files.newInputStream(pcapFile);
    ){
      p = Pcap.openStream(in);
      p.loop(new PacketHandler(){
        @Override public boolean nextPacket(final Packet packet) throws IOException {
          block:{
            try{
              // Get the packet's arrival time in milliseconds
              long timestamp = packet.getArrivalTime()/1000;
              if (timestamp>1000000000000000L){
                timestamp/=1000;
              }
              if (timestamp<=afterMillis){
                start = start==-1?afterMillis:Math.min(start, afterMillis);
                end = end==-1?afterMillis:Math.max(end, afterMillis);
                break block;
              }
              start = start==-1?timestamp:Math.min(start, timestamp);
              end = end==-1?timestamp:Math.max(end, timestamp);
              final byte[] data = packet.getPayload().getRawArray();
              if (data.length<=23){ break block; }
              // Ensure ip.proto is UDP
              if (data[23]!=(byte)17){
                break block;
              }
              // Ensure eth.type is IPv4
              if (data[12]!=(byte)8 || data[13]!=(byte)0){
                break block;
              }
              // Index of the first byte after the IPv4 header
              final int x = 14+((data[14]&0x0F)<<2);
              if (data.length<=x+11){ break block; }
              // Ensure bvlc.type is BACnet/IP
              if (data[x+8]!=(byte)0x81){
                break block;
              }
              // Get IP and port information
              int srcIP = Utility.getAddressBits(data,26);
              int dstIP = Utility.getAddressBits(data,30);
              int srcPort = ((data[x]&0xFF)<<8)|(data[x+1]&0xFF);
              int dstPort = ((data[x+2]&0xFF)<<8)|(data[x+3]&0xFF);
              // Apply filters
              String category = null;
              if (filters==null){
                category = "N/A".intern();
              }else{
                for (PacketFilter f: filters){
                  if (f.accept(srcIP, dstIP, dstPort)){
                    category = f.category;
                    break;
                  }
                }
                if (category==null){
                  break block;
                }
              }
              // bvlc.length
              final int length = (((data[x+10]&0xFF)<<8)|(data[x+11]&0xFF))+x+8;
              if (data.length<length){ break block; }
              // bvlc.function
              switch (data[x+9]){
                // bvlc.function = Original-Broadcast-NPDU
                case (byte)0x0B:{
                  if (length<=x+13){ break block; }
                  handleBroadcast(timestamp, data, length, category, x+13, srcIP, srcPort);
                  break block;
                }
                // bvlc.function = Forwarded-NPDU
                case (byte)0x04:{
                  if (length<=x+19){ break block; }
                  srcIP = Utility.getAddressBits(data, x+12);
                  srcPort = ((data[x+16]&0xFF)<<8)|(data[x+17]&0xFF);
                  handleBroadcast(timestamp, data, length, category, x+19, srcIP, srcPort);
                  break block;
                }
                default:{
                  break block;
                }
              }
            }catch(Throwable t){
              Initializer.log(t);
            }
          }
          return !Initializer.isKilled();
        }
      });
    }catch(Throwable t){
      Initializer.log(t);
    }finally{
      if (p!=null){
        p.close();
      }
    }
    // Attempt to reasonably limit RAM usage
    if (packets.size()>CACHE_LIMIT){
      sortByTimeDesc();
      packets.subList(CACHE_LIMIT, packets.size()).clear();
      start = packets.get(CACHE_LIMIT-1).time;
    }
  }
  /**
   * Internal utility method to handle parsing a single broadcast packet.
   */
  private void handleBroadcast(long time, byte[] data, int length, String category, int x, int srcIP, int srcPort){
    // if -1, undefined, otherwise this is an integer between 1 and 65534 (inclusive)
    int srcNetwork = -1;
    // if -1, undefined, else if <256, this is a MAC address, otherwise this is an IP address
    int srcAddress = -1;
    // bacnet.control
    {
      final int control = data[x]&0xFF;
      // handle network layer messages separately
      if ((control&0x80)!=0){
        if (length<=++x){ return; }
        // bacnet.mesgtyp
        final int messageType = data[x]&0xFF;
        switch (messageType){
          // bacnet.mesgtyp = Who-Is-Router-To-Network
          case 0:{
            if (length==x+1){
              // Global
              packets.add(new WhoIsRouter(category, time, srcIP, srcPort, srcNetwork, srcAddress, -messageType-1, -1));
            }else{
              if (length!=x+3){ return; }
              final int network = ((data[x+1]&0xFF)<<8)|(data[x+2]&0xFF);
              packets.add(new WhoIsRouter(category, time, srcIP, srcPort, srcNetwork, srcAddress, -messageType-1, network));
            }
            return;
          }
          // bacnet.mesgtyp = I-Am-Router-To-Network
          case 1:{
            ++x;
            if (length==x || (length-x)%2!=0){ return; }
            final int[] networks = new int[(length-x)>>1];
            for (int i=0;i<networks.length;++i,x+=2){
              networks[i] = ((data[x]&0xFF)<<8)|(data[x+1]&0xFF);
            }
            packets.add(new IAmRouter(category, time, srcIP, srcPort, srcNetwork, srcAddress, -messageType-1, networks));
            return;
          }
          default:{
            packets.add(new Broadcast(category, time, srcIP, srcPort, srcNetwork, srcAddress, -messageType-1));
            return;
          }
        }
      }
      final boolean src = ((control>>3)&1)==1;
      final boolean dst = ((control>>5)&1)==1;
      if (dst){
        x+=3;
        if (length<=x){ return; }
        x+=data[x]&0xFF;
      }
      if (src){
        // retrieve source network and MAC information
        if (length<=x+3){ return; }
        srcNetwork = ((data[x+1]&0xFF)<<8)|(data[x+2]&0xFF);
        int l = data[x+3]&0xFF;
        if (length<=x+l+3){ return; }
        if (l==1){
          srcAddress = data[x+4]&0xFF;
        }else if (l==6){
          srcAddress = Utility.getAddressBits(data, x+4);
        }
        x+=l+3;
      }
      if (dst){
        ++x;
      }
    }
    if (length<=x+2){ return; }
    // bacapp.type = Unconfirmed-REQ
    if (data[++x]!=(byte)16){
      return;
    }
    // bacapp.unconfirmed_service
    final int service = data[++x]&0xFF;
    switch (service){
      // bacapp.unconfirmed_service = unconfirmedCOVNotification
      case 2:{
        if (length<=++x){ return; }
        x+=(data[x]&7)+3;
        if (length<=x+7){ return; }
        final int instance = ((data[x]&0x3F)<<16)|((data[x+1]&0xFF)<<8)|(data[x+2]&0xFF);
        final int objectType = ((data[x+4]&0xFF)<<2)|((data[x+5]&0xC0)>>>6);
        final int objectNumber = ((data[x+5]&0x3F)<<16)|((data[x+6]&0xFF)<<8)|(data[x+7]&0xFF);
        packets.add(new UnconfirmedCOV(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, instance, objectType, objectNumber));
        return;
      }
      // bacapp.unconfirmed_service = who-Has
      case 7:{
        int low = 4194303;
        int high = 4194303;
        int objectType = -1;
        int objectNumber = -1;
        String objectName = "";
        while (++x<length){
          // bacapp.context_tag_number
          final int contextTag = (data[x]&0xF0)>>>4;
          switch (contextTag){
            // Device instance range low limit
            case 0:{
              low = 0;
              int l = data[x]&7;
              if (length<=x+l+1){ return; }
              for (int i=0;i<l;++i){
                low<<=8;
                low|=data[++x]&0xFF;
              }
              break;
            }
            // Device instance range high limit
            case 1:{
              high = 0;
              int l = data[x]&7;
              if (length<=x+l+1){ return; }
              for (int i=0;i<l;++i){
                high<<=8;
                high|=data[++x]&0xFF;
              }
              break;
            }
            // Object identifier
            case 2:{
              if (length<=x+4){ return; }
              objectType = ((data[x+1]&0xFF)<<2)|((data[x+2]&0xC0)>>>6);
              objectNumber = ((data[x+2]&0x3F)<<16)|((data[x+3]&0xFF)<<8)|(data[x+4]&0xFF);
              x+=4;
              break;
            }
            // Object name
            case 3:{
              if (length<=++x){ return; }
              final int nameLen = data[x]&0xFF;
              if (nameLen==0){ break; }
              if (length<=x+nameLen){ return; }
              final int charsetID = data[x+1]&0xFF;
              objectName = new String(data, x+2, nameLen-1, Constants.getCharset(charsetID));
              x+=nameLen;
              break;
            }
            default:{
              return;
            }
          }
        }
        if (objectType==-1 && objectNumber==-1 && objectName.isEmpty() && low==4194303 || low>high){
          return;
        }
        packets.add(new WhoHas(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, low, high, objectType, objectNumber, objectName));
        return;
      }
      // bacapp.unconfirmed_service = i-Have
      case 1:{
        if (length<=x+12){ return; }
        final int instance = ((data[x+3]&0x3F)<<16)|((data[x+4]&0xFF)<<8)|(data[x+5]&0xFF);
        final int type = ((data[x+7]&0xFF)<<2)|((data[x+8]&0xC0)>>>6);
        final int number = ((data[x+8]&0x3F)<<16)|((data[x+9]&0xFF)<<8)|(data[x+10]&0xFF);
        final int nameLen = data[x+12]&0xFF;
        if (length!=x+13+nameLen){ return; }
        if (nameLen==0){
          packets.add(new IHave(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, instance, type, number, ""));
        }else{
          final int charsetID = data[x+13]&0xFF;
          final String name = new String(data, x+14, nameLen-1, Constants.getCharset(charsetID));
          packets.add(new IHave(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, instance, type, number, name));
        }
        return;
      }
      // bacapp.unconfirmed_service = who-Is
      case 8:{
        if (length==x+1){
          // Global who-Is
          packets.add(new WhoIs(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, 4194303, 4194303));
        }else{
          if (length<=x+1){ return; }
          // Number of bytes in the low limit
          int low = 0, high = 0;
          {
            int i;
            int l = data[++x]&7;
            if (length<=x+l+1){ return; }
            for (i=0;i<l;++i){
              low<<=8;
              low|=data[++x]&0xFF;
            }
            l = data[++x]&7;
            if (length<=x+l){ return; }
            for (i=0;i<l;++i){
              high<<=8;
              high|=data[++x]&0xFF;
            }
          }
          if (length!=x+1){ return; }
          packets.add(new WhoIs(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, low, high));
        }
        return;
      }
      // bacapp.unconfirmed_service = i-Am
      case 0:{
        if (length<=x+6){ return; }
        final int instance = ((data[x+3]&0x3F)<<16)|((data[x+4]&0xFF)<<8)|(data[x+5]&0xFF);
        x+=6;
        x+=(data[x]&7)+1;
        if (length<=x){ return; }
        x+=(data[x]&7)+1;
        if (length<=x){ return; }
        int l = data[x]&7;
        int vendorID = 0;
        if (length<=x+l){ return; }
        for (int i=0;i<l;++i){
          vendorID<<=8;
          vendorID|=data[++x]&0xFF;
        }
        if (length!=x+1){ return; }
        packets.add(new IAm(category, time, srcIP, srcPort, srcNetwork, srcAddress, service, instance, vendorID));
        return;
      }
      default:{
        packets.add(new Broadcast(category, time, srcIP, srcPort, srcNetwork, srcAddress, service));
        return;
      }
    }
  }
}