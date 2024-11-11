package aces.webctrl.wireshark.core;
import javax.servlet.*;
import java.nio.file.*;
import com.controlj.green.addonsupport.*;
/**
 * This class contains most of the life-cycle management logic for this add-on.
 */
public class Initializer implements ServletContextListener {
  /** Whether to log to stdout or to a log file unique to this add-on */
  private final static boolean LOG_TO_STDOUT = false;
  /** Encourages the program to log extra information in some cases. */
  public final static boolean VERBOSE = false;
  /** Contains basic information about this addon */
  public volatile static AddOnInfo info = null;
  /** The name of this addon */
  private volatile static String name;
  /** Prefix used for constructing relative URL paths */
  private volatile static String prefix;
  /** Path to the private directory for this addon */
  private volatile static Path root;
  /** Logger for this addon */
  private volatile static FileLogger logger;
  /** Primary processing thread */
  private volatile static Thread mainThread = null;
  /** Whether the primary thread is active */
  private volatile static boolean running = false;
  /** Whether to stop the primary thread */
  private volatile static boolean stop = false;
  /** Used to manually trigger capture checks */
  public final static Object waitObj = new Object();
  /** Used to manually trigger capture checks */
  private volatile static boolean goNow = false;
  /** Primary container to cache packets collected in the last 3 days */
  public final static PacketCache cache = new PacketCache(259200000L);
  /**
   * @return a rough estimate for the amount of RAM used by this add-on (in bytes).
   */
  public static long estimateRAM(){
    long x = 3145728L;
    x+=1024L*SavedData.alarms.size();
    x+=64L*SavedData.points.size();
    x+=112L*cache.capture.packets.size();
    return x;
  }
  /**
   * Entry point of this add-on.
   */
  @Override public void contextInitialized(ServletContextEvent sce){
    info = AddOnInfo.getAddOnInfo();
    name = info.getName();
    prefix = '/'+name+'/';
    root = info.getPrivateDir().toPath();
    logger = info.getDateStampLogger();
    SavedData.init(root.resolve("params.dat"));
    mainThread = new Thread(){
      public void run(){
        long nextSave = 0;
        long a,b;
        while (!stop){
          try{
            b = System.currentTimeMillis();
            a = b+(nextSave==0?5000L:10805000L);
            do {
              synchronized(waitObj){
                if (!goNow && !stop){
                  waitObj.wait(Math.min(a-b,60000L));
                }
              }
              if (goNow || stop){
                break;
              }
              b = System.currentTimeMillis();
            } while (b<a);
            if (stop){
              break;
            }
            if ((a=System.currentTimeMillis())>nextSave){
              nextSave = a+905000L;
              SavedData.saveData();
              if (VERBOSE){
                log("Add-on data saved.");
              }
            }
            if (VERBOSE){
              log("Loading packets...");
            }
            cache.update();
            if (cache.valid){
              if (VERBOSE){
                log("Analyzing packets...");
              }
              final StatPoint sp = cache.getStats();
              SavedData.add(sp);
              new PacketAnalysis(sp);
              if (VERBOSE){
                log("Analysis complete.");
              }
            }else if (VERBOSE){
              log("Packet cache is invalid.");
            }
          }catch(InterruptedException e){}catch(Throwable t){
            Initializer.log(t);
          }
          goNow = false;
        }
        running = false;
      }
    };
    running = true;
    mainThread.start();
  }
  /**
   * Releases resources.
   */
  @Override public void contextDestroyed(ServletContextEvent sce){
    stop = true;
    trigger();
    if (running){
      SavedData.saveData();
      try{
        mainThread.interrupt();
        mainThread.join();
      }catch(InterruptedException e){}
    }
    SavedData.saveData();
  }
  /**
   * Trigger capture check to start immediately.
   */
  public static void trigger(){
    synchronized (waitObj){
      cache.resetNetwork();
      goNow = true;
      waitObj.notifyAll();
    }
  }
  /**
   * @return whether any active threads should be killed.
   */
  public static boolean isKilled(){
    return stop;
  }
  /**
   * @return the name of this application.
   */
  public static String getName(){
    return name;
  }
  /**
   * @return the prefix used for constructing relative URL paths.
   */
  public static String getPrefix(){
    return prefix;
  }
  /**
   * Logs a message.
   */
  public synchronized static void log(String str){
    if (LOG_TO_STDOUT){
      System.out.println(str);
    }else{
      logger.println(str);
    }
  }
  /**
   * Logs an error.
   */
  public synchronized static void log(Throwable t){
    if (LOG_TO_STDOUT){
      t.printStackTrace();
    }else{
      logger.println(t);
    }
  }
}