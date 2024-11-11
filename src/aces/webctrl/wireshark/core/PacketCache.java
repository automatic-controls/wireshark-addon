package aces.webctrl.wireshark.core;
import aces.webctrl.wireshark.broadcast.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import java.util.function.*;
/**
 * This class wraps a {@link PacketCapture} to provide a rolling window that always shows the latest packets in some time interval.
 */
public class PacketCache {
  /** A list of BACnet/IP connection details. */
  public volatile ArrayList<ConnectionParams> connections = null;
  /** A map of routers on the network tree keyed by IP address. */
  public volatile TreeMap<Integer,Router> routers = null;
  /** The primary wrapped PacketCapture object. */
  public volatile PacketCapture capture = new PacketCapture();
  /** Specifies the size of the rolling window used for this cache. */
  private volatile long duration;
  /** Whether the last update yielded a valid result. */
  public volatile boolean valid;
  /** The timestamp in epoch milliseconds of the last update. */
  private volatile long lastUpdate = 0;
  /** The timestamp in epoch milliseconds of the previous network detail reload. */
  private volatile long lastNetworkUpdate = 0;
  /**
   * Created a new PacketCache with a rolling window of the specified duration in milliseconds.
   * Do not specify a duration less than or equal to 10 minutes.
   */
  public PacketCache(final long duration){
    this.duration = duration;
  }
  /**
   * Causes the next update to recompute network information.
   */
  public void resetNetwork(){
    lastNetworkUpdate = 0;
  }
  /**
   * @return some computed statistics about the packets cached in this object.
   */
  public synchronized StatPoint getStats(){
    final StatPoint sp = new StatPoint(capture.start, capture.end);
    for (Broadcast b: capture.packets){
      b.incrementStats(sp);
    }
    return sp;
  }
  /**
   * Recomputes the rolling window of packets.
   * Old packets are removed from the cache.
   * The latest PCAP files are parsed to grab new packets and add them to the cache.
   */
  public synchronized void update() throws Throwable {
    final long currentTime = System.currentTimeMillis();
    if (currentTime-lastUpdate<4500L){
      return;
    }
    valid = false;
    final long _afterMillis = currentTime-duration;
    if (!capture.packets.isEmpty()){
      final int len = capture.packets.size();
      int i = Collections.binarySearch(capture.packets, new Broadcast(_afterMillis));
      if (i<0){
        i = -i-1;
      }
      if (i<len){
        capture.packets.subList(i, len).clear();
        capture.start = capture.packets.get(i-1).time;
      }
    }
    final long afterMillis = capture.packets.isEmpty()?_afterMillis:capture.packets.get(0).time;
    if (Initializer.isKilled()){ return; }
    Path dir = SavedData.captureDir;
    if (dir!=null && Files.exists(dir)){
      lastUpdate = currentTime;
      final ArrayList<Path> captures = new ArrayList<Path>(32);
      try(
        Stream<Path> s = Files.list(dir);
      ){
        s.forEach(new Consumer<Path>(){
          @Override public void accept(Path p){
            try{
              if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".pcap") && Files.getLastModifiedTime(p).toMillis()+60000L>afterMillis){
                captures.add(p);
              }
            }catch(Throwable t){}
          }
        });
      }
      if (!captures.isEmpty()){
        if (Initializer.isKilled()){ return; }
        if (connections==null || routers==null || currentTime-lastNetworkUpdate>90000L){
          lastNetworkUpdate = currentTime;
          try(
            DatabaseLink dl = new DatabaseLink(true);
          ){
            if (Initializer.isKilled()){ return; }
            connections = dl.getConnectionDetails();
            if (Initializer.isKilled()){ return; }
            routers = dl.getRouters();
          }
          if (Initializer.isKilled()){ return; }
        }
        ArrayList<PacketFilter> filters = new ArrayList<PacketFilter>(8);
        for (ConnectionParams connection:connections){
          connection.resolve(routers);
          connection.addFilters(filters);
        }
        for (Path cap:captures){
          capture.load(cap, filters, afterMillis);
          if (Initializer.isKilled()){ return; }
        }
        capture.sortByTimeDesc();
        if (!capture.packets.isEmpty() && capture.start+600000L<capture.end){
          valid = true;
        }
      }
    }
  }
}