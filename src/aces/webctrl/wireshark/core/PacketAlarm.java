package aces.webctrl.wireshark.core;
import java.util.*;
/**
 * Each object of this class represents a single alarm generated from anomolies detected in packet captures.
 * The first time an error is detected, a notification is sent out (if necessary), and an alarm is added to the queue.
 * Repeated notifications are not sent after initial activation if the problem persists.
 * When the error is no longer detected for 8 consecutive checks, the corresponding alarm is removed from the queue.
 * After an alarm is removed from the queue, it may be reactivated the next time a problem is detected.
 * Users may dismiss an active alarm from the web UI if the user believes the root cause has been remedied.
 * After 3.5 days, dismissed alarms are removed from the queue.
 * The alarm queue is stored at {@link SavedData#alarms}.
 * This class also contains some static constants related to the types of errors that may be detected.
 */
public class PacketAlarm implements Comparable<PacketAlarm> {


  // The following section specifies alarm type bitmasks used for determining whether to send notifications along with SavedData.alarmFlags.
  // <BEGIN>

  /**
   * An I-Am packet is said to be prompted if it was preceded by a corresponding Who-Is packet in the last {@value #_MAX_RESPONSE_TIME} milliseconds.
   * The same definition also applies to I-Am-Router and I-Have packets.
   */
  public final static int _MAX_RESPONSE_TIME = 5000;
  /** Counter used to increment bitmasking constants. */
  private volatile static long X = 1L;
  /**
   * <b>Intention:</b> When FDR is unnecessarily configured on one or more BACnet/IP connections, this alarm is triggered.
   * <p>It is a requirement that FDR is actually configured for this alarm to trigger.
   * If FDR is configured, then any one of the following conditions will activate the alarm:
   * <ul>
   * <li>A router with non-null {@link Router#modelName modelName} shares a subnet with the WebCTRL server.</li>
   * <li>The number of singular Who-Is packets with multiple response I-Am packets exceeds the number of singular Who-Is packets with one response.</li>
   * </ul>
   */
  public final static long FDR_UNNECESSARY = X;
  /**
   * When more than {@value #_EXCESS_OTHER_TRAFFIC}% of broadcast traffic falls outside of the services recognized here, then this alarm is triggered.
   * Recognized services are listed below:
   * <ul>
   * <li>Who-Is</li>
   * <li>I-Am</li>
   * <li>Who-Is-Router-To-Network</li>
   * <li>I-Am-Router-To-Network</li>
   * <li>Who-Has</li>
   * <li>I-Have</li>
   * <li>Unconfirmed-COV</li>
   * </ul>
   */
  public final static long EXCESS_OTHER_TRAFFIC = X*=2;
  /** @see #EXCESS_OTHER_TRAFFIC */
  public final static int _EXCESS_OTHER_TRAFFIC = 6;
  /**
   * When any Router-Busy-To-Network packets are detected like {@code Broadcast.service==-5}, this alarm is triggered.
   * One alarm is triggered for each source.
   */
  public final static long ROUTER_BUSY_TO_NETWORK = X*=2;
  /**
   * If more than one unprompted I-Am packet is sent every {@value #_I_AM_SPAM} seconds for a single device instance, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long I_AM_SPAM = X*=2;
  /** @see #I_AM_SPAM */
  public final static int _I_AM_SPAM = 120;
  /**
   * If more than one answered Who-Is packet with identical low and high limits is sent every {@value #_WHO_IS_SPAM} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long WHO_IS_SPAM = X*=2;
  /** @see #WHO_IS_SPAM */
  public final static int _WHO_IS_SPAM = 300;
  /**
   * If more than one unanswered Who-Is packet with identical low and high limits is sent every {@value #_UNANSWERED_WHO_IS} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long UNANSWERED_WHO_IS = X*=2;
  /** @see #UNANSWERED_WHO_IS */
  public final static int _UNANSWERED_WHO_IS = 120;
  /**
   * If two or more I-Am packets for the same instance number have different sources and occur within {@value #_DUPLICATE_INSTANCE_NUMBER} seconds of each other, then this alarm is triggered.
   */
  public final static long DUPLICATE_INSTANCE_NUMBER = X*=2;
  /** @see #DUPLICATE_INSTANCE_NUMBER */
  public final static int _DUPLICATE_INSTANCE_NUMBER = 6;
  /**
   * If the average number of prompted I-Am responses per Who-Is packet for a given instance number exceeds {@value #_I_AM_DOUBLING}, then this alarm is triggered assuming the following conditions are also met:
   * <ul>
   * <li>The {@link #FDR_UNNECESSARY} alarm is not active.</li>
   * <li>A {@link #DUPLICATE_INSTANCE_NUMBER} alarm is not active for the specified instance number.</li>
   * </ul>
   * This alarm may indicate a duplicate device instance under the same BACnet/IP router, or it may indicate BBMD problems.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long I_AM_DOUBLING = X*=2;
  /** @see #I_AM_DOUBLING */
  public final static double _I_AM_DOUBLING = 1.5;
  /**
   * If the average I-Am response time to Who-Is packets for a specific device instance is greater than {@value #_I_AM_SLOW} milliseconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long I_AM_SLOW = X*=2;
  /** @see #I_AM_SLOW */
  public final static int _I_AM_SLOW = 2000;
  /**
   * If more than one unprompted I-Am-Router packet is sent every {@value #_I_AM_ROUTER_SPAM} seconds for a single network number, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long I_AM_ROUTER_SPAM = X*=2;
  /** @see #I_AM_ROUTER_SPAM */
  public final static int _I_AM_ROUTER_SPAM = 120;
  /**
   * If more than one answered Who-Is-Router packet for the same network number is sent every {@value #_WHO_IS_ROUTER_SPAM} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long WHO_IS_ROUTER_SPAM = X*=2;
  /** @see #WHO_IS_ROUTER_SPAM */
  public final static int _WHO_IS_ROUTER_SPAM = 300;
  /**
   * If more than one unanswered Who-Is-Router packet for the same network number is sent every {@value #_UNANSWERED_WHO_IS_ROUTER} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long UNANSWERED_WHO_IS_ROUTER = X*=2;
  /** @see #UNANSWERED_WHO_IS_ROUTER */
  public final static int _UNANSWERED_WHO_IS_ROUTER = 120;
  /**
   * If two or more I-Am-Network packets for the same network number have different sources and occur within {@value #_DUPLICATE_NETWORK_NUMBER} seconds of each other, then this alarm is triggered.
   */
  public final static long DUPLICATE_NETWORK_NUMBER = X*=2;
  /** @see #DUPLICATE_NETWORK_NUMBER */
  public final static int _DUPLICATE_NETWORK_NUMBER = 6;
  /**
   * If more than one unprompted I-Have packet is sent every {@value #_I_HAVE_SPAM} seconds for a single object, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long I_HAVE_SPAM = X*=2;
  /** @see #I_HAVE_SPAM */
  public final static int _I_HAVE_SPAM = 120;
  /**
   * If more than one answered Who-Has packet for the same object is sent every {@value #_WHO_HAS_SPAM} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long WHO_HAS_SPAM = X*=2;
  /** @see #WHO_HAS_SPAM */
  public final static int _WHO_HAS_SPAM = 300;
  /**
   * If more than one unanswered Who-Has packet for the same object is sent every {@value #_UNANSWERED_WHO_HAS} seconds, then this alarm is triggered.
   * @see #_MAX_RESPONSE_TIME
   */
  public final static long UNANSWERED_WHO_HAS = X*=2;
  /** @see #UNANSWERED_WHO_HAS */
  public final static int _UNANSWERED_WHO_HAS = 120;
  /**
   * If more than one Unconfirmed-COV-Notification packet for the same object is sent every {@value #_UNCONFIRMED_COV_SPAM} seconds, then this alarm is triggered.
   */
  public final static long UNCONFIRMED_COV_SPAM = X*=2;
  /** @see #UNCONFIRMED_COV_SPAM */
  public final static int _UNCONFIRMED_COV_SPAM = 20;
  // <END>


  /** The epoch milliseconds recorded at the time this alarm was activated. */
  private volatile long timestamp = System.currentTimeMillis();
  /** The string which uniquely identifies this alarm. */
  private volatile String identifier;
  /** A display-friendly header to succinctly describe this alarm. */
  private volatile String header;
  /** HTML which fully describes this alarm and its possible causes. */
  private volatile String desc;
  /** Whether an email notification should be sent out for this alarm at the next processing interval. */
  private volatile boolean notify;
  /** Whether an administrator has manually dismissed this alarm. */
  private volatile boolean dismissed = false;
  /** Specifies how long dismissed alarms remain in the queue. */
  private volatile long expiry = 0L;
  /** Counter which is decremented to 0 when the root error ceases to exist. */
  private volatile int checks = 8;
  /**
   * Create a new PacketAlarm.
   */
  public PacketAlarm(String identifier, String header, String desc, boolean notify){
    this.identifier = identifier;
    this.header = header;
    this.desc = desc;
    this.notify = notify;
  }
  /**
   * Appends the contents of this alarm as JSON to the given StringBuilder.
   */
  public void toString(StringBuilder sb){
    sb.append('{');
    sb.append("\"id\":\"").append(Utility.escapeJSON(identifier)).append("\",");
    sb.append("\"header\":\"").append(Utility.escapeJSON(header)).append("\",");
    sb.append("\"desc\":\"").append(Utility.escapeJSON(desc)).append("\",");
    sb.append("\"time\":").append(timestamp).append(",");
    sb.append("\"dismissed\":").append(dismissed).append(",");
    sb.append("\"current\":").append(checks==8);
    sb.append('}');
  }
  /**
   * Write this object's data to the given SerializationStream.
   */
  public void serialize(SerializationStream s){
    s.write(identifier);
    s.write(header);
    s.write(desc);
    s.write(notify);
    s.write(dismissed);
    s.write(expiry);
    s.write(checks);
    s.write(timestamp);
  }
  /**
   * @return a PacketAlarm retrieved from the given SerializationStream.
   */
  public static PacketAlarm deserialize(SerializationStream s){
    final PacketAlarm a = new PacketAlarm(s.readString(), s.readString(), s.readString(), s.readBoolean());
    a.dismissed = s.readBoolean();
    a.expiry = s.readLong();
    a.checks = s.readInt();
    a.timestamp = s.readLong();
    return a;
  }
  /**
   * @return the epoch milliseconds recorded at the time this alarm was created.
   */
  public long getTimestamp(){
    return timestamp;
  }
  /**
   * Performs a natural ordering by timestamp ascending.
   */
  @Override public int compareTo(PacketAlarm alarm){
    if (timestamp==alarm.timestamp){
      return identifier.compareTo(alarm.identifier);
    }else{
      return Long.compare(timestamp, alarm.timestamp);
    }
  }
  /**
   * @return a string which uniquely identifies this alarm.
   */
  public String getIdentifier(){
    return identifier;
  }
  /**
   * @return a display-friendly header to succinctly describe this alarm.
   */
  public String getHeader(){
    return header;
  }
  /**
   * @return text which fully describes this alarm and its possible causes.
   */
  public String getDescription(){
    return desc;
  }
  /**
   * @return whether this alarm has been dismissed by an administrator.
   */
  public boolean isDismissed(){
    return dismissed;
  }
  /**
   * Dismisses this alarm.
   */
  public void dismiss(){
    if (!dismissed){
      dismissed = true;
      expiry = System.currentTimeMillis()+302400000L;
      Initializer.log("Alarm dismissed: "+identifier);
    }
  }
  /**
   * @return the expiration in epoch milliseconds that specifies when this alarm will be removed from the queue.
   *         This value only has meaning when the alarm has been dismissed. Otherwise, {@code 0} will be returned.
   */
  public long getExpiry(){
    return expiry;
  }
  /**
   * Processes new alarm detections and merges them into the current alarm queue.
   */
  public static void merge(HashMap<String,PacketAlarm> newDetections){
    synchronized (SavedData.alarms){
      removeExpired(SavedData.alarms.values());
      {
        final Iterator<PacketAlarm> iter = SavedData.alarms.values().iterator();
        PacketAlarm a,b;
        while (iter.hasNext()){
          a = iter.next();
          b = newDetections.get(a.identifier);
          if (b!=null){
            a.checks = 8;
            a.desc = b.desc;
            a.header = b.header;
          }else if (--a.checks<=0){
            iter.remove();
            if (!a.dismissed){
              Initializer.log("Alarm returned to normal: "+a.identifier);
            }
          }
        }
      }
      for (PacketAlarm alarm: newDetections.values()){
        if (!SavedData.alarms.containsKey(alarm.identifier)){
          SavedData.alarms.put(alarm.identifier, alarm);
          Initializer.log("Alarm activated: "+alarm.identifier);
          if (Initializer.VERBOSE){
            Initializer.log((alarm.getHeader()+"\n"+alarm.getDescription()).replace("\n",System.lineSeparator()));
          }
        }
      }
      triggerAlarms(SavedData.alarms.values());
    }
  }
  /**
   * Clears the alarm cache.
   */
  public static void clear(){
    synchronized (SavedData.alarms){
      SavedData.alarms.clear();
    }
  }
  /**
   * Sends email notifications for alarms in the given collection when necessary.
   */
  private static void triggerAlarms(Collection<PacketAlarm> alarms){
    boolean suc = true;
    if (SavedData.isEmailConfigured()){
      int has = 0;
      for (PacketAlarm alarm: alarms){
        if (alarm.notify){
          ++has;
        }
      }
      if (has>0){
        final StringBuilder sb = new StringBuilder(128);
        sb.append(has+" alarm"+(has>1?"s have":" has")+" been raised by the WiresharkAnalyzer add-on.\n");
        for (PacketAlarm alarm: alarms){
          if (alarm.notify){
            sb.append('\n').append(alarm.header.replace("\n", " - "));
          }
        }
        suc = SavedData.sendEmail(sb.toString());
      }
    }
    if (suc){
      for (PacketAlarm alarm: alarms){
        alarm.notify = false;
      }
    }
  }
  /**
   * Removes expired alarms from the given collection.
   */
  private static void removeExpired(Collection<PacketAlarm> alarms){
    final Iterator<PacketAlarm> iter = alarms.iterator();
    final long currentTime = System.currentTimeMillis();
    long exp;
    while (iter.hasNext()){
      exp = iter.next().getExpiry();
      if (exp>0L && exp<currentTime){
        iter.remove();
      }
    }
  }
}