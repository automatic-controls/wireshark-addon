package aces.webctrl.wireshark.core;
import java.io.*;
import java.util.*;
import java.util.concurrent.locks.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.channels.*;
import com.controlj.green.core.email.*;
/**
 * Controls how this add-on's information is written and read from the saved data file.
 */
public class SavedData {
  /** The path to the saved data file. */
  private static volatile Path file;
  /** The email subject for alarm notifications. */
  public static volatile String emailSubject = "";
  /** The email recipients for alarm notifications. */
  public static volatile String[] emailRecipients = new String[]{};
  /** The path to where relevant PCAP files are stored. */
  public static volatile String captureDir_ = "";
  /** The path to where relevant PCAP files are stored. */
  public static volatile Path captureDir = null;
  /** A cache of active and dismissed alarms. */
  public final static HashMap<String,PacketAlarm> alarms = new HashMap<String,PacketAlarm>(32);
  /** Specifies whether to send notifications for various alarm types. */
  public static volatile long alarmFlags = -1L;
  /** A cache of historical packet statistics. */
  public final static ArrayList<StatPoint> points = new ArrayList<StatPoint>(3072);
  /** Controls access to {@link SavedData#points}. */
  public final static ReentrantReadWriteLock pointLock = new ReentrantReadWriteLock();

  public static volatile int _MAX_RESPONSE_TIME;
  public static volatile int _EXCESS_OTHER_TRAFFIC;
  public static volatile int _I_AM_SPAM;
  public static volatile int _WHO_IS_SPAM;
  public static volatile int _UNANSWERED_WHO_IS;
  public static volatile int _DUPLICATE_INSTANCE_NUMBER;
  public static volatile double _I_AM_DOUBLING;
  public static volatile int _I_AM_SLOW;
  public static volatile int _I_AM_ROUTER_SPAM;
  public static volatile int _WHO_IS_ROUTER_SPAM;
  public static volatile int _UNANSWERED_WHO_IS_ROUTER;
  public static volatile int _DUPLICATE_NETWORK_NUMBER;
  public static volatile int _I_HAVE_SPAM;
  public static volatile int _WHO_HAS_SPAM;
  public static volatile int _UNANSWERED_WHO_HAS;
  public static volatile int _UNCONFIRMED_COV_SPAM;

  /**
   * Reset various error thresholds.
   */
  public static void resetToDefault(){
    _MAX_RESPONSE_TIME = PacketAlarm._MAX_RESPONSE_TIME;
    _EXCESS_OTHER_TRAFFIC = PacketAlarm._EXCESS_OTHER_TRAFFIC;
    _I_AM_SPAM = PacketAlarm._I_AM_SPAM;
    _WHO_IS_SPAM = PacketAlarm._WHO_IS_SPAM;
    _UNANSWERED_WHO_IS = PacketAlarm._UNANSWERED_WHO_IS;
    _DUPLICATE_INSTANCE_NUMBER = PacketAlarm._DUPLICATE_INSTANCE_NUMBER;
    _I_AM_DOUBLING = PacketAlarm._I_AM_DOUBLING;
    _I_AM_SLOW = PacketAlarm._I_AM_SLOW;
    _I_AM_ROUTER_SPAM = PacketAlarm._I_AM_ROUTER_SPAM;
    _WHO_IS_ROUTER_SPAM = PacketAlarm._WHO_IS_ROUTER_SPAM;
    _UNANSWERED_WHO_IS_ROUTER = PacketAlarm._UNANSWERED_WHO_IS_ROUTER;
    _DUPLICATE_NETWORK_NUMBER = PacketAlarm._DUPLICATE_NETWORK_NUMBER;
    _I_HAVE_SPAM = PacketAlarm._I_HAVE_SPAM;
    _WHO_HAS_SPAM = PacketAlarm._WHO_HAS_SPAM;
    _UNANSWERED_WHO_HAS = PacketAlarm._UNANSWERED_WHO_HAS;
    _UNCONFIRMED_COV_SPAM = PacketAlarm._UNCONFIRMED_COV_SPAM;
  }
  /**
   * Sets the path to the saved data file and attempts to load any available data.
   */
  public static void init(Path file){
    SavedData.file = file;
    resetToDefault();
    loadData();
  }
  /**
   * Add a StatPoint to the historical statistic cache.
   */
  public static void add(StatPoint sp){
    pointLock.writeLock().lock();
    try {
      // Delete data points older than 365 days
      int i = Collections.binarySearch(points, new StatPoint(System.currentTimeMillis()-31536000000L));
      if (i<0){
        i = -i-1;
      }else{
        ++i;
      }
      if (i>0){
        points.subList(0, i).clear();
      }
      points.add(sp);
      points.sort(null);
    }finally{
      pointLock.writeLock().unlock();
    }
  }
  /**
   * @return the most recently recorded StatPoint.
   */
  public static StatPoint getLatestStats(){
    pointLock.readLock().lock();
    try {
      if (points.isEmpty()){
        return null;
      }else{
        return points.get(points.size()-1);
      }
    }finally{
      pointLock.readLock().unlock();
    }
  }
  /**
   * Writes all historical statistics to the given PrintWriter as a JSON array.
   */
  public static void writeStats(PrintWriter writer){
    pointLock.readLock().lock();
    try {
      writer.print('[');
      boolean first = true;
      for (StatPoint sp: points){
        if (first){
          first = false;
        }else{
          writer.println(',');
        }
        sp.toString(writer);
      }
      writer.print(']');
    }finally{
      pointLock.readLock().unlock();
    }
  }
  /**
   * @return whether the email subject and recipients of this add-on have been properly configured.
   */
  public static boolean isEmailConfigured(){
    return !emailSubject.isBlank() && emailRecipients.length>0;
  }
  /**
   * Send an email containing the specified message.
   * @return {@code true} if the email was sent successfully or if email is not configured, or {@code false} if an exception was encountered while attempting to send the email.
   */
  public static boolean sendEmail(String message){
    final String emailSubject = SavedData.emailSubject;
    final String[] emailRecipients = SavedData.emailRecipients;
    if (emailRecipients.length==0 || emailSubject.isBlank()){
      return true;
    }
    try{
      EmailParametersBuilder pb = EmailServiceFactory.createParametersBuilder();
      pb.withSubject(emailSubject);
      pb.withToRecipients(emailRecipients);
      pb.withMessageContents(message);
      pb.withMessageMimeType("text/plain");
      EmailServiceFactory.getService().sendEmail(pb.build());
      return true;
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
  }
  /**
   * Internally used to check that loaded parameters are reasonable.
   */
  private final static int check(int x, int min, int max, int def){
    return x>=min&&x<=max?x:def;
  }
  /**
   * Set the path to the directory contains relevant PCAP files.
   */
  public static boolean setCaptureDir(String path){
    captureDir_ = path;
    if (captureDir_.isBlank()){
      captureDir_ = "";
      captureDir = null;
      return false;
    }
    try{
      captureDir = Paths.get(captureDir_);
      return true;
    }catch(Throwable t){
      captureDir = null;
      return false;
    }
  }
  /**
   * Load information from the saved data file.
   * @return whether data was loaded successfully.
   */
  private static boolean loadData(){
    if (file==null){
      return false;
    }
    try{
      if (Files.exists(file)){
        byte[] arr;
        synchronized(SavedData.class){
          arr = Files.readAllBytes(file);
        }
        final SerializationStream s = new SerializationStream(arr);
        setCaptureDir(s.readString());
        emailSubject = s.readString();
        emailRecipients = new String[check(s.readInt(), 0, 4096, 0)];
        for (int i=0;i<emailRecipients.length;++i){
          emailRecipients[i] = s.readString();
        }
        alarmFlags = s.readLong();
        int i;
        {
          PacketAlarm a;
          for (i=s.readInt();i>0;--i){
            a = PacketAlarm.deserialize(s);
            alarms.put(a.getIdentifier(), a);
          }
        }
        _MAX_RESPONSE_TIME = s.readInt();
        _EXCESS_OTHER_TRAFFIC = s.readInt();
        _I_AM_SPAM = s.readInt();
        _WHO_IS_SPAM = s.readInt();
        _UNANSWERED_WHO_IS = s.readInt();
        _DUPLICATE_INSTANCE_NUMBER = s.readInt();
        _I_AM_DOUBLING = s.readDouble();
        _I_AM_SLOW = s.readInt();
        _I_AM_ROUTER_SPAM = s.readInt();
        _WHO_IS_ROUTER_SPAM = s.readInt();
        _UNANSWERED_WHO_IS_ROUTER = s.readInt();
        _DUPLICATE_NETWORK_NUMBER = s.readInt();
        _I_HAVE_SPAM = s.readInt();
        _WHO_HAS_SPAM = s.readInt();
        _UNANSWERED_WHO_HAS = s.readInt();
        _UNCONFIRMED_COV_SPAM = s.readInt();
        i = s.readInt();
        points.ensureCapacity(i+32);
        for (;i>0;--i){
          points.add(StatPoint.deserialize(s));
        }
        points.sort(null);
        if (!s.end()){
          Initializer.log("Data file corrupted.");
          return false;
        }
      }
      return true;
    }catch(Throwable t){
      Initializer.log("Error occurred while loading data.");
      Initializer.log(t);
      return false;
    }
  }
  /**
   * Writes information to the saved data file.
   * @return whether data was saved successfully.
   */
  public static boolean saveData(){
    if (file==null){
      return false;
    }
    try{
      final SerializationStream s = new SerializationStream(1024, true);
      s.write(captureDir_);
      s.write(emailSubject);
      final String[] arr = emailRecipients;
      s.write(arr.length);
      for (int i=0;i<arr.length;++i){
        s.write(arr[i]);
      }
      s.write(alarmFlags);
      synchronized (alarms){
        s.write(alarms.size());
        for (PacketAlarm a: alarms.values()){
          a.serialize(s);
        }
      }
      s.write(_MAX_RESPONSE_TIME);
      s.write(_EXCESS_OTHER_TRAFFIC);
      s.write(_I_AM_SPAM);
      s.write(_WHO_IS_SPAM);
      s.write(_UNANSWERED_WHO_IS);
      s.write(_DUPLICATE_INSTANCE_NUMBER);
      s.write(_I_AM_DOUBLING);
      s.write(_I_AM_SLOW);
      s.write(_I_AM_ROUTER_SPAM);
      s.write(_WHO_IS_ROUTER_SPAM);
      s.write(_UNANSWERED_WHO_IS_ROUTER);
      s.write(_DUPLICATE_NETWORK_NUMBER);
      s.write(_I_HAVE_SPAM);
      s.write(_WHO_HAS_SPAM);
      s.write(_UNANSWERED_WHO_HAS);
      s.write(_UNCONFIRMED_COV_SPAM);
      pointLock.readLock().lock();
      try {
        s.write(points.size());
        for (StatPoint sp: points){
          sp.serialize(s);
        }
      }finally{
        pointLock.readLock().unlock();
      }
      final ByteBuffer buf = s.getBuffer();
      synchronized(SavedData.class){
        try(
          FileChannel out = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        ){
          while (buf.hasRemaining()){
            out.write(buf);
          }
        }
      }
      return true;
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
  }
}