package aces.webctrl.wireshark.core;
import aces.webctrl.wireshark.broadcast.*;
import java.util.*;
import java.util.function.*;
import java.text.*;
public class PacketAnalysis {
  public final static DecimalFormat df = new DecimalFormat("0.00");
  private final HashMap<String,PacketAlarm> alarms = new HashMap<String,PacketAlarm>(32);
  private final PacketCache cache = Initializer.cache;
  private final ArrayList<Broadcast> packets = cache.capture.packets;
  private final int len = packets.size();
  private final long flags = SavedData.alarmFlags;
  private volatile int startLim;
  private volatile int endLim;
  private double duration;
  private volatile StatPoint sp;
  public PacketAnalysis(StatPoint sp){
    this.sp = sp;
    startLim = Collections.binarySearch(packets, new Broadcast(cache.capture.start+SavedData._MAX_RESPONSE_TIME));
    if (startLim<0){
      startLim = -startLim-1;
    }
    endLim = Collections.binarySearch(packets, new Broadcast(cache.capture.end-SavedData._MAX_RESPONSE_TIME));
    if (endLim<0){
      endLim = -endLim-1;
    }
    duration = (sp.end-sp.start)/1000L;
    checkFDR();
    checkExcessOtherTraffic();
    checkRouterBusyToNetwork();
    checkIAmSpam();
    checkWhoIsSpam();
    checkUnansweredWhoIs();
    checkDuplicateInstanceNumber();
    checkIAmDoubling();
    checkIAmSlow();
    checkIAmRouterSpam();
    checkWhoIsRouterSpam();
    checkUnansweredWhoIsRouter();
    checkDuplicateNetworkNumber();
    checkIHaveSpam();
    checkWhoHasSpam();
    checkUnansweredWhoHas();
    checkUnconfirmedCOVSpam();
    PacketAlarm.merge(alarms);
  }
  public void addAlarm(PacketAlarm alarm){
    alarms.put(alarm.getIdentifier(), alarm);
  }
  public String resolveIP(int ip, boolean ipRegardless){
    Router r = cache.routers.get(ip);
    if (r==null){
      return Utility.getIPv4(ip);
    }else if (ipRegardless){
      return r.displayName+" ("+Utility.getIPv4(ip)+")";
    }else{
      return r.displayName;
    }
  }
  public void checkFDR(){
    final boolean notify = (flags&PacketAlarm.FDR_UNNECESSARY)!=0L;
    Collection<Router> routers = null;
    boolean FDR = false;
    for (ConnectionParams cp: cache.connections){
      if (cp.fdr){
        FDR = true;
        if (routers==null){
          routers = cache.routers.values();
        }
        for (Router r: routers){
          if (r.modelName!=null && Utility.subnetContains(cp.ipAddressBits, cp.subnetMaskBits, r.ipAddressBits)){
            addAlarm(new PacketAlarm(
              "FDRU",
              "FDR Unnecessary",
              "FDR is currently configured on a BACnet/IP connection.\nThis is unnecessary because "+r.referenceName+
              " is already on the WebCTRL server's subnet.\nPlease disable FDR.",
              notify
            ));
            return;
          }
        }
      }
    }
    if (FDR){
      Broadcast b;
      WhoIs x;
      IAm y;
      long t;
      int i,j,k;
      int single = 0;
      int multiple = 0;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIs){
          x = (WhoIs)b;
          if (x.low==x.high && !x.isGlobal()){
            t = x.time+SavedData._MAX_RESPONSE_TIME;
            k = 0;
            for (j=i-1;j>=0;--j){
              b = packets.get(j);
              if (b.time>t){
                break;
              }else if (b instanceof IAm){
                y = (IAm)b;
                if (x.low==y.instance){
                  ++k;
                }
              }else if (b instanceof WhoIs && ((WhoIs)b).matches(x.low)){
                break;
              }
            }
            if (k==1){
              ++single;
            }else if (k>1){
              ++multiple;
            }
          }
        }
      }
      if (multiple>single && multiple>8){
        addAlarm(new PacketAlarm(
          "FDRU",
          "FDR Unnecessary",
          "FDR is currently configured on a BACnet/IP connection.\nIt appears that FDR may be unnecessary because "+df.format((double)multiple/(single+multiple))+
          "% of Who-Is packets are receiving more than one response.\nPlease investigate and disable FDR if appropriate."+
          "\nbacapp.unconfirmed_service==0 || (bacapp.unconfirmed_service==8 && bacapp.who_is.low_limit==bacapp.who_is.high_limit && bacapp.who_is.low_limit!=4194303)",
          notify
        ));
      }
    }
  }
  public void checkExcessOtherTraffic(){
    final boolean notify = (flags&PacketAlarm.EXCESS_OTHER_TRAFFIC)!=0L;
    final int total =
      sp.iAm+
      sp.iAmRouter+
      sp.iHave+
      sp.other+
      sp.unconfirmedCOV+
      sp.whoHas+
      sp.whoIs+
      sp.whoIsRouter;
    if (sp.other*100>total*SavedData._EXCESS_OTHER_TRAFFIC){
      double p = (double)sp.other/total*100;
      addAlarm(new PacketAlarm(
        "EOT",
        "Excess of Unknown Traffic",
        df.format(p)+"% of broadcast traffic is unrecognized, which is above the "+SavedData._EXCESS_OTHER_TRAFFIC+"% threshold.\n"+
        "Recognizable broadcast types include Who-Is, I-Am, Who-Is-Router-To-Network, I-Am-Router-To-Network, Who-Has, I-Have, and Unconfirmed-COV.\n"+
        "This alarm does not necessarily imply network problems exist, but it can suggest that additional investigation is warranted.\n"+
        "bvlc.function in {0x4,0xB} && (!bacnet.mesgtyp || bacnet.mesgtyp not in {0,1}) && (!bacapp.unconfirmed_service || bacapp.unconfirmed_service not in {0,1,2,7,8})",
        notify
      ));
    }
  }
  public void checkRouterBusyToNetwork(){
    final boolean notify = (flags&PacketAlarm.ROUTER_BUSY_TO_NETWORK)!=0L;
    String id;
    for (Broadcast b: packets){
      if (b.service==-5 && !alarms.containsKey(id="RBTN:"+b.getSourceID())){
        addAlarm(new PacketAlarm(
          id,
          "Busy\n"+resolveIP(b.srcIP,false),
          "A Router-Busy-To-Network broadcast has been received from "+resolveIP(b.srcIP,true)+
          (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
          (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+
          ".\nThis indicates the router is overwhelmed and cannot process additional requests.\n"+
          "bacnet.mesgtyp==4",
          notify
        ));
      }
    }
  }
  public void checkIAmSpam(){
    final boolean notify = (flags&PacketAlarm.I_AM_SPAM)!=0L;
    final HashMap<Integer,Integer> map = new HashMap<Integer,Integer>();
    final HashMap<Integer,IAm> samples = new HashMap<Integer,IAm>();
    {
      final BiFunction<Integer,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Integer k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      IAm x;
      WhoIs y;
      long t;
      int i,j;
      boolean bb;
      for (i=0;i<startLim;++i){
        b = packets.get(i);
        if (b instanceof IAm){
          x = (IAm)b;
          t = x.time-SavedData._MAX_RESPONSE_TIME;
          bb = true;
          for (j=i+1;j<len;++j){
            b = packets.get(j);
            if (b.time<t){
              break;
            }else if (b instanceof WhoIs){
              y = (WhoIs)b;
              if (y.matches(x.instance)){
                bb = false;
                break;
              }
            }
          }
          if (bb && map.compute(x.instance, func)==1){
            samples.put(x.instance, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._I_AM_SPAM);
    map.forEach(new BiConsumer<Integer,Integer>(){
      @Override public void accept(Integer k, Integer v){
        if (v>lim){
          final IAm b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "IAS:"+Integer.toHexString(k),
            "I-Am Spam\n"+k,
            "Device instance "+k+" is broadcasting one unprompted I-Am packet every "+df.format(x)+" seconds, on average.\n"+
            "The device vendor is "+b.getVendor()+" ("+b.vendor+").\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+"."+
            "\nbacapp.unconfirmed_service==0 && bacapp.instance_number=="+k,
            notify
          ));
        }
      }
    });
  }
  public void checkWhoIsSpam(){
    final boolean notify = (flags&PacketAlarm.WHO_IS_SPAM)!=0L;
    final HashMap<Long,Integer> map = new HashMap<>();
    final HashMap<Long,WhoIs> samples = new HashMap<>();
    {
      final BiFunction<Long,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Long k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoIs x;
      IAm y;
      long t,k;
      int i,j;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIs){
          x = (WhoIs)b;
          ans = x.isGlobal();
          if (!ans){
            t = x.time+SavedData._MAX_RESPONSE_TIME;
            for (j=i-1;j>=0;--j){
              b = packets.get(j);
              if (b.time>t){
                break;
              }else if (b instanceof IAm){
                y = (IAm)b;
                if (x.matches(y.instance)){
                  ans = true;
                  break;
                }
              }
            }
          }
          if (ans){
            k = ((long)x.high)&0xFFFFFFFFL;
            k<<=32;
            k|=((long)x.low)&0xFFFFFFFFL;
            map.compute(k, func);
            samples.put(k, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._WHO_IS_SPAM);
    map.forEach(new BiConsumer<Long,Integer>(){
      @Override public void accept(Long k, Integer v){
        if (v>lim){
          final WhoIs b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "WIS:"+Utility.pad(Integer.toHexString(b.high), "0", 6)+Integer.toHexString(b.low),
            "Who-Is Spam\n"+(b.isGlobal()?"Global":(b.low==b.high?b.low:b.low+":"+b.high)),
            "This Who-Is broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+"."+
            "\nbacapp.unconfirmed_service==8 && "+(b.isGlobal()?
              "((!bacapp.who_is.low_limit && !bacapp.who_is.high_limit) || (bacapp.who_is.low_limit==0 && bacapp.who_is.high_limit>=4194302) || bacapp.who_is.low_limit==4194303)":
              "bacapp.who_is.low_limit=="+b.low+" && bacapp.who_is.high_limit=="+b.high
            ),
            notify
          ));
        }
      }
    });
  }
  public void checkUnansweredWhoIs(){
    final boolean notify = (flags&PacketAlarm.UNANSWERED_WHO_IS)!=0L;
    final HashMap<Long,Integer> map = new HashMap<>();
    final HashMap<Long,WhoIs> samples = new HashMap<>();
    {
      final BiFunction<Long,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Long k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoIs x;
      IAm y;
      long t,k;
      int i,j;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIs){
          x = (WhoIs)b;
          ans = x.isGlobal();
          if (!ans){
            t = x.time+SavedData._MAX_RESPONSE_TIME;
            for (j=i-1;j>=0;--j){
              b = packets.get(j);
              if (b.time>t){
                break;
              }else if (b instanceof IAm){
                y = (IAm)b;
                if (x.matches(y.instance)){
                  ans = true;
                  break;
                }
              }
            }
            if (!ans){
              k = ((long)x.high)&0xFFFFFFFFL;
              k<<=32;
              k|=((long)x.low)&0xFFFFFFFFL;
              map.compute(k, func);
              samples.put(k, x);
            }
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._UNANSWERED_WHO_IS);
    map.forEach(new BiConsumer<Long,Integer>(){
      @Override public void accept(Long k, Integer v){
        if (v>lim){
          final WhoIs b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "UWI:"+Utility.pad(Integer.toHexString(b.high), "0", 6)+Integer.toHexString(b.low),
            "Unanswered Who-Is\n"+(b.low==b.high?b.low:b.low+":"+b.high),
            "This Who-Is broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+"."+
            "\nbacapp.unconfirmed_service==8 && bacapp.who_is.low_limit=="+b.low+" && bacapp.who_is.high_limit=="+b.high,
            notify
          ));
        }
      }
    });
  }
  public void checkDuplicateInstanceNumber(){
    final boolean notify = (flags&PacketAlarm.DUPLICATE_INSTANCE_NUMBER)!=0L;
    final HashMap<Integer,int[]> map = new HashMap<>();
    {
      Broadcast b;
      IAm x,y;
      int i,j;
      long t;
      int[] arr;
      final long milli = SavedData._DUPLICATE_INSTANCE_NUMBER*1000L;
      for (i=0;i<len;++i){
        b = packets.get(i);
        if (b instanceof IAm){
          x = (IAm)b;
          if (!map.containsKey(x.instance)){
            t = x.time-milli;
            for (j=i+1;j<len;++j){
              b = packets.get(j);
              if (b.time<t){
                break;
              }else if (b instanceof IAm){
                y = (IAm)b;
                if (x.instance==y.instance && (x.srcIP!=y.srcIP || x.srcNetwork!=y.srcNetwork || x.srcAddress!=y.srcAddress)){
                  arr = new int[8];
                  arr[0] = x.srcIP;
                  arr[1] = x.srcNetwork;
                  arr[2] = x.srcAddress;
                  arr[3] = x.vendor;
                  arr[4] = y.srcIP;
                  arr[5] = y.srcNetwork;
                  arr[6] = y.srcAddress;
                  arr[7] = y.vendor;
                  map.put(x.instance, arr);
                  break;
                }
              }
            }
          }
        }
      }
    }
    map.forEach(new BiConsumer<Integer,int[]>(){
      @Override public void accept(Integer k, int[] v){
        addAlarm(new PacketAlarm(
          "DIN:"+Integer.toHexString(k),
          "Duplicate Instance\n"+k,
          "I-Am packets for instance number "+k+" have been detected with inconsistent sources.\n"+
          "The first source is "+resolveIP(v[0],true)+
          (v[1]<0?"":" on network "+v[1])+
          (v[2]<0?"":" with MAC "+((v[2]&0xFF000000)==0?v[2]:Utility.getIPv4(v[2])))+
          " from vendor "+Constants.getVendor(v[3])+" ("+v[3]+").\n"+
          "The second source is "+resolveIP(v[4],true)+
          (v[5]<0?"":" on network "+v[5])+
          (v[6]<0?"":" with MAC "+((v[6]&0xFF000000)==0?v[6]:Utility.getIPv4(v[6])))+
          " from vendor "+Constants.getVendor(v[7])+" ("+v[7]+")."+
          "\nbacapp.unconfirmed_service==0 && bacapp.instance_number=="+k,
          notify
        ));
      }
    });
  }
  public void checkIAmDoubling(){
    if (!alarms.containsKey("FDRU")){
      final boolean notify = (flags&PacketAlarm.I_AM_DOUBLING)!=0L;
      final HashMap<Integer,int[]> map = new HashMap<>(256);
      final HashMap<Integer,IAm> samples = new HashMap<>(256);
      {
        Broadcast b;
        WhoIs x;
        IAm y = null;
        long t;
        int i,j,k;
        for (i=len-1;i>=endLim;--i){
          b = packets.get(i);
          if (b instanceof WhoIs){
            x = (WhoIs)b;
            if (x.low==x.high && !x.isGlobal() && !alarms.containsKey("DIN:"+Integer.toHexString(x.low))){
              t = x.time+SavedData._MAX_RESPONSE_TIME;
              k = 0;
              for (j=i-1;j>=0;--j){
                b = packets.get(j);
                if (b.time>t){
                  break;
                }else if (b instanceof IAm){
                  y = (IAm)b;
                  if (x.low==y.instance){
                    ++k;
                  }
                }else if (b instanceof WhoIs && ((WhoIs)b).matches(x.low)){
                  break;
                }
              }
              if (k>0){
                final int num = k;
                if (map.compute(x.low, new BiFunction<Integer, int[], int[]>(){
                  @Override public int[] apply(Integer key, int[] value){
                    if (value==null){
                      value = new int[]{num,1};
                    }else{
                      value[0]+=num;
                      ++value[1];
                    }
                    return value;
                  }
                })[1]==1){
                  samples.put(x.low, y);
                }
              }
            }
          }
        }
      }
      map.forEach(new BiConsumer<Integer,int[]>(){
        @Override public void accept(Integer k, int[] v){
          final double d = (double)v[0]/v[1];
          if (d>SavedData._I_AM_DOUBLING && v[1]>4){
            final IAm x = samples.get(k);
            addAlarm(new PacketAlarm(
              "IAD:"+Integer.toHexString(k),
              "I-Am Multiplier\n"+k,
              "There are "+df.format(d)+" I-Am packets for every Who-Is packet to instance "+k+", on average.\n"+
              "This suggests there may be BBMD routing issues (e.g, two BBMDs in a single subnet).\n"+
              "The I-Am packet source appears to be "+resolveIP(x.srcIP,true)+
              (x.srcNetwork==-1?"":" on network "+x.srcNetwork)+
              (x.srcAddress==-1?"":" with MAC "+((x.srcAddress&0xFF000000)==0?x.srcAddress:Utility.getIPv4(x.srcAddress)))+
              " from vendor "+Constants.getVendor(x.vendor)+" ("+x.vendor+").\n"+
              "(bacapp.unconfirmed_service==0 && bacapp.instance_number=="+k+") || (bacapp.unconfirmed_service==8 && bacapp.who_is.low_limit==bacapp.who_is.high_limit && bacapp.who_is.low_limit=="+k+")",
              notify
            ));
          }
        }
      });
    }
  }
  public void checkIAmSlow(){
    final boolean notify = (flags&PacketAlarm.I_AM_SLOW)!=0L;
    final HashMap<Integer,long[]> map = new HashMap<>(256);
    final HashMap<Integer,IAm> samples = new HashMap<>(256);
    {
      Broadcast b;
      WhoIs x,xx;
      IAm y;
      long t;
      int i,j;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIs){
          x = (WhoIs)b;
          t = x.time+SavedData._MAX_RESPONSE_TIME;
          for (j=i-1;j>=0;--j){
            b = packets.get(j);
            if (b.time>t){
              break;
            }else if (b instanceof IAm){
              y = (IAm)b;
              if (x.matches(y.instance)){
                final long num = y.time-x.time;
                if (map.compute(y.instance, new BiFunction<Integer, long[], long[]>(){
                  @Override public long[] apply(Integer key, long[] value){
                    if (value==null){
                      value = new long[]{num,1L};
                    }else{
                      value[0]+=num;
                      ++value[1];
                    }
                    return value;
                  }
                })[1]==1){
                  samples.put(y.instance, y);
                }
              }
            }else if (b instanceof WhoIs){
              xx = (WhoIs)b;
              if (x.isGlobal() || xx.isGlobal() || x.low<=xx.high && x.high>=xx.low){
                break;
              }
            }
          }
        }
      }
    }
    map.forEach(new BiConsumer<Integer,long[]>(){
      @Override public void accept(Integer k, long[] v){
        final long d = (long)((double)v[0]/v[1]);
        if (d>SavedData._I_AM_SLOW && v[1]>4){
          final IAm x = samples.get(k);
          addAlarm(new PacketAlarm(
            "IASL:"+Integer.toHexString(k),
            "I-Am Slow\n"+k,
            "Device instance "+k+" is taking a long time ("+d+" ms, on average) to respond to Who-Is packets.\n"+
            "The I-Am packet source appears to be "+resolveIP(x.srcIP,true)+
            (x.srcNetwork==-1?"":" on network "+x.srcNetwork)+
            (x.srcAddress==-1?"":" with MAC "+((x.srcAddress&0xFF000000)==0?x.srcAddress:Utility.getIPv4(x.srcAddress)))+
            " from vendor "+Constants.getVendor(x.vendor)+" ("+x.vendor+").\n"+
            "bacapp.unconfirmed_service==0 && bacapp.instance_number=="+k,
            notify
          ));
        }
      }
    });
  }
  public void checkIAmRouterSpam(){
    final boolean notify = (flags&PacketAlarm.I_AM_ROUTER_SPAM)!=0L;
    final HashMap<Integer,Integer> map = new HashMap<Integer,Integer>();
    final HashMap<Integer,IAmRouter> samples = new HashMap<Integer,IAmRouter>();
    {
      final BiFunction<Integer,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Integer k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      IAmRouter x;
      WhoIsRouter y;
      long t;
      int i,j;
      boolean bb;
      for (i=0;i<startLim;++i){
        b = packets.get(i);
        if (b instanceof IAmRouter){
          x = (IAmRouter)b;
          t = x.time-SavedData._MAX_RESPONSE_TIME;
          bb = true;
          for (j=i+1;j<len;++j){
            b = packets.get(j);
            if (b.time<t){
              break;
            }else if (b instanceof WhoIsRouter){
              y = (WhoIsRouter)b;
              if (x.hasNetwork(y.network)){
                bb = false;
                break;
              }
            }
          }
          if (bb){
            for (j=0;j<x.networks.length;++j){
              if (map.compute(x.networks[j], func)==1){
                samples.put(x.networks[j], x);
              }
            }
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._I_AM_ROUTER_SPAM);
    map.forEach(new BiConsumer<Integer,Integer>(){
      @Override public void accept(Integer k, Integer v){
        if (v>lim){
          final IAmRouter b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "IARS:"+Integer.toHexString(k),
            "I-Am-Router Spam\n"+k,
            "The router to network "+k+" is broadcasting one unprompted I-Am-Router-To-Network packet every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacnet.mesgtyp==1 && bacnet.dnet=="+k,
            notify
          ));
        }
      }
    });
  }
  public void checkWhoIsRouterSpam(){
    final boolean notify = (flags&PacketAlarm.WHO_IS_ROUTER_SPAM)!=0L;
    final HashMap<Integer,Integer> map = new HashMap<>();
    final HashMap<Integer,WhoIsRouter> samples = new HashMap<>();
    {
      final BiFunction<Integer,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Integer k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoIsRouter x;
      IAmRouter y;
      long t;
      int i,j;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIsRouter){
          x = (WhoIsRouter)b;
          ans = x.isGlobal();
          if (!ans){
            t = x.time+SavedData._MAX_RESPONSE_TIME;
            for (j=i-1;j>=0;--j){
              b = packets.get(j);
              if (b.time>t){
                break;
              }else if (b instanceof IAmRouter){
                y = (IAmRouter)b;
                if (y.hasNetwork(x.network)){
                  ans = true;
                  break;
                }
              }
            }
          }
          if (ans){
            map.compute(x.network, func);
            samples.put(x.network, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._WHO_IS_ROUTER_SPAM);
    map.forEach(new BiConsumer<Integer,Integer>(){
      @Override public void accept(Integer k, Integer v){
        if (v>lim){
          final WhoIsRouter b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "WIRS:"+Integer.toHexString(k),
            "Who-Is-Router Spam\n"+(b.isGlobal()?"Global":k),
            "This Who-Is-Router-To-Network broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacnet.mesgtyp==0 && "+(b.isGlobal()?"!bacnet.dnet":"bacnet.dnet=="+k),
            notify
          ));
        }
      }
    });
  }
  public void checkUnansweredWhoIsRouter(){
    final boolean notify = (flags&PacketAlarm.UNANSWERED_WHO_IS_ROUTER)!=0L;
    final HashMap<Integer,Integer> map = new HashMap<>();
    final HashMap<Integer,WhoIsRouter> samples = new HashMap<>();
    {
      final BiFunction<Integer,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Integer k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoIsRouter x;
      IAmRouter y;
      long t;
      int i,j;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoIsRouter){
          x = (WhoIsRouter)b;
          ans = x.isGlobal();
          if (!ans){
            t = x.time+SavedData._MAX_RESPONSE_TIME;
            for (j=i-1;j>=0;--j){
              b = packets.get(j);
              if (b.time>t){
                break;
              }else if (b instanceof IAmRouter){
                y = (IAmRouter)b;
                if (y.hasNetwork(x.network)){
                  ans = true;
                  break;
                }
              }
            }
            if (!ans){
              map.compute(x.network, func);
              samples.put(x.network, x);
            }
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._UNANSWERED_WHO_IS_ROUTER);
    map.forEach(new BiConsumer<Integer,Integer>(){
      @Override public void accept(Integer k, Integer v){
        if (v>lim){
          final WhoIsRouter b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "UWIR:"+Integer.toHexString(b.network),
            "Unanswered Who-Is-Router\n"+b.network,
            "This Who-Is-Router-To-Network broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacnet.mesgtyp==0 && "+(b.isGlobal()?"!bacnet.dnet":"bacnet.dnet=="+b.network),
            notify
          ));
        }
      }
    });
  }
  public void checkDuplicateNetworkNumber(){
    final boolean notify = (flags&PacketAlarm.DUPLICATE_NETWORK_NUMBER)!=0L;
    final HashMap<Integer,int[]> map = new HashMap<>();
    {
      Broadcast b;
      IAmRouter x,y;
      int i,j,k;
      long t;
      int[] arr;
      final HashSet<Integer> set = new HashSet<>();
      final long milli = SavedData._DUPLICATE_NETWORK_NUMBER*1000L;
      for (i=0;i<len;++i){
        b = packets.get(i);
        if (b instanceof IAmRouter){
          x = (IAmRouter)b;
          for (j=0;j<x.networks.length;++j){
            if (!map.containsKey(x.networks[j])){
              set.add(x.networks[j]);
            }
          }
          if (!set.isEmpty()){
            t = x.time-milli;
            for (j=i+1;j<len;++j){
              b = packets.get(j);
              if (b.time<t){
                break;
              }else if (b instanceof IAmRouter && (x.srcIP!=b.srcIP || x.srcNetwork!=b.srcNetwork || x.srcAddress!=b.srcAddress)){
                y = (IAmRouter)b;
                arr = null;
                for (k=0;k<y.networks.length;++k){
                  if (set.remove(y.networks[k])){
                    if (arr==null){
                      arr = new int[6];
                      arr[0] = x.srcIP;
                      arr[1] = x.srcNetwork;
                      arr[2] = x.srcAddress;
                      arr[3] = y.srcIP;
                      arr[4] = y.srcNetwork;
                      arr[5] = y.srcAddress;
                    }
                    map.put(y.networks[k], arr);
                    if (set.isEmpty()){
                      break;
                    }
                  }
                }
                if (set.isEmpty()){
                  break;
                }
              }
            }
          }
          set.clear();
        }
      }
    }
    map.forEach(new BiConsumer<Integer,int[]>(){
      @Override public void accept(Integer k, int[] v){
        addAlarm(new PacketAlarm(
          "DNN:"+Integer.toHexString(k),
          "Duplicate Network\n"+k,
          "I-Am-Router-To-Network packets for network number "+k+" have been detected with inconsistent sources.\n"+
          "The first source is "+resolveIP(v[0],true)+
          (v[1]<0?"":" on network "+v[1])+
          (v[2]<0?"":" with MAC "+((v[2]&0xFF000000)==0?v[2]:Utility.getIPv4(v[2])))+
          ".\nThe second source is "+resolveIP(v[3],true)+
          (v[4]<0?"":" on network "+v[4])+
          (v[5]<0?"":" with MAC "+((v[5]&0xFF000000)==0?v[5]:Utility.getIPv4(v[5])))+".\n"+
          "bacnet.mesgtyp==1 && bacnet.dnet=="+k,
          notify
        ));
      }
    });
  }
  public void checkIHaveSpam(){
    final boolean notify = (flags&PacketAlarm.I_HAVE_SPAM)!=0L;
    final HashMap<Long,Integer> map = new HashMap<>();
    final HashMap<Long,IHave> samples = new HashMap<>();
    {
      final BiFunction<Long,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Long k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      IHave x;
      WhoHas y;
      long s,t;
      int i,j;
      boolean bb;
      for (i=0;i<startLim;++i){
        b = packets.get(i);
        if (b instanceof IHave){
          x = (IHave)b;
          t = x.time-SavedData._MAX_RESPONSE_TIME;
          bb = true;
          for (j=i+1;j<len;++j){
            b = packets.get(j);
            if (b.time<t){
              break;
            }else if (b instanceof WhoHas){
              y = (WhoHas)b;
              if (y.matches(x)){
                bb = false;
                break;
              }
            }
          }
          if (bb && map.compute(s=x.getGUID(), func)==1){
            samples.put(s, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._I_HAVE_SPAM);
    map.forEach(new BiConsumer<Long,Integer>(){
      @Override public void accept(Long k, Integer v){
        if (v>lim){
          final IHave b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "IHS:"+Long.toHexString(k),
            "I-Have Spam\n"+b.instance,
            "Device instance "+b.instance+" is broadcasting one unprompted I-Have packet for object \""+
            b.getObjectType()+","+b.objectNumber+(b.name.isEmpty()?"":","+b.name)+"\" every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacapp.unconfirmed_service==1 && bacapp.instance_number=="+b.instance+" && bacapp.instance_number=="+b.objectNumber+" && bacapp.objectType=="+b.objectType,
            notify
          ));
        }
      }
    });
  }
  public void checkWhoHasSpam(){
    final boolean notify = (flags&PacketAlarm.WHO_HAS_SPAM)!=0L;
    final HashMap<WhoHas.GUID,Integer> map = new HashMap<>();
    final HashMap<WhoHas.GUID,WhoHas> samples = new HashMap<>();
    {
      final BiFunction<WhoHas.GUID,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(WhoHas.GUID k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoHas x;
      IHave y;
      long t;
      int i,j;
      WhoHas.GUID guid;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoHas){
          x = (WhoHas)b;
          ans = false;
          t = x.time+SavedData._MAX_RESPONSE_TIME;
          for (j=i-1;j>=0;--j){
            b = packets.get(j);
            if (b.time>t){
              break;
            }else if (b instanceof IHave){
              y = (IHave)b;
              if (x.matches(y)){
                ans = true;
                break;
              }
            }
          }
          if (ans){
            guid = x.getGUID();
            map.compute(guid, func);
            samples.put(guid, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._WHO_HAS_SPAM);
    map.forEach(new BiConsumer<WhoHas.GUID,Integer>(){
      @Override public void accept(WhoHas.GUID k, Integer v){
        if (v>lim){
          final WhoHas b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "WHS:"+k,
            "Who-Has Spam\n"+(b.low==4194303?"*":(b.low==b.high?b.low:b.low+"-"+b.high))+
            (b.objectType==-1?"":","+b.getObjectType()+":"+b.objectNumber)+
            (b.objectName.isEmpty()?"":","+b.objectName),
            "This Who-Has broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacapp.unconfirmed_service==7"+
            (b.objectType==-1?" && !bacapp.objectType":" && bacapp.instance_number=="+b.objectNumber+" && bacapp.objectType=="+b.objectType)+
            (b.objectName.isEmpty()?" && (!bacapp.object_name || bacapp.object_name==\"\")":" && bacapp.object_name==\""+b.objectName.replace("\\","\\\\").replace("\"","\\\"")+"\""),
            notify
          ));
        }
      }
    });
  }
  public void checkUnansweredWhoHas(){
    final boolean notify = (flags&PacketAlarm.UNANSWERED_WHO_HAS)!=0L;
    final HashMap<WhoHas.GUID,Integer> map = new HashMap<>();
    final HashMap<WhoHas.GUID,WhoHas> samples = new HashMap<>();
    {
      final BiFunction<WhoHas.GUID,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(WhoHas.GUID k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      WhoHas x;
      IHave y;
      long t;
      int i,j;
      WhoHas.GUID guid;
      boolean ans;
      for (i=len-1;i>=endLim;--i){
        b = packets.get(i);
        if (b instanceof WhoHas){
          x = (WhoHas)b;
          ans = false;
          t = x.time+SavedData._MAX_RESPONSE_TIME;
          for (j=i-1;j>=0;--j){
            b = packets.get(j);
            if (b.time>t){
              break;
            }else if (b instanceof IHave){
              y = (IHave)b;
              if (x.matches(y)){
                ans = true;
                break;
              }
            }
          }
          if (!ans){
            guid = x.getGUID();
            map.compute(guid, func);
            samples.put(guid, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._UNANSWERED_WHO_HAS);
    map.forEach(new BiConsumer<WhoHas.GUID,Integer>(){
      @Override public void accept(WhoHas.GUID k, Integer v){
        if (v>lim){
          final WhoHas b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "UWH:"+k,
            "Unanswered Who-Has\n"+(b.low==4194303?"*":(b.low==b.high?b.low:b.low+"-"+b.high))+
            (b.objectType==-1?"":","+b.getObjectType()+":"+b.objectNumber)+
            (b.objectName.isEmpty()?"":","+b.objectName),
            "This Who-Has broadcast occurs every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacapp.unconfirmed_service==7"+
            (b.objectType==-1?" && !bacapp.objectType":" && bacapp.instance_number=="+b.objectNumber+" && bacapp.objectType=="+b.objectType)+
            (b.objectName.isEmpty()?" && (!bacapp.object_name || bacapp.object_name==\"\")":" && bacapp.object_name==\""+b.objectName.replace("\\","\\\\").replace("\"","\\\"")+"\""),
            notify
          ));
        }
      }
    });
  }
  public void checkUnconfirmedCOVSpam(){
    final boolean notify = (flags&PacketAlarm.UNCONFIRMED_COV_SPAM)!=0L;
    final HashMap<Long,Integer> map = new HashMap<>();
    final HashMap<Long,UnconfirmedCOV> samples = new HashMap<>();
    {
      final BiFunction<Long,Integer,Integer> func = new BiFunction<>(){
        @Override public Integer apply(Long k, Integer v){
          return v==null?1:v+1;
        }
      };
      Broadcast b;
      UnconfirmedCOV x;
      long s;
      int i;
      for (i=0;i<len;++i){
        b = packets.get(i);
        if (b instanceof UnconfirmedCOV){
          x = (UnconfirmedCOV)b;
          if (map.compute(s=x.getGUID(), func)==1){
            samples.put(s, x);
          }
        }
      }
    }
    final int lim = (int)(duration/SavedData._UNCONFIRMED_COV_SPAM);
    map.forEach(new BiConsumer<Long,Integer>(){
      @Override public void accept(Long k, Integer v){
        if (v>lim){
          final UnconfirmedCOV b = samples.get(k);
          final double x = (double)duration/v;
          addAlarm(new PacketAlarm(
            "UCOVS:"+Long.toHexString(k),
            "Unconfirmed-COV Spam\n"+b.instance,
            "Device instance "+b.instance+" is broadcasting one Unconfirmed-COV-Notification packet for object \""+
            b.getObjectType()+","+b.objectNumber+"\" every "+df.format(x)+" seconds, on average.\n"+
            "At least one of these packets originate from "+resolveIP(b.srcIP,true)+
            (b.srcNetwork==-1?"":" on network "+b.srcNetwork)+
            (b.srcAddress==-1?"":" with MAC "+((b.srcAddress&0xFF000000)==0?b.srcAddress:Utility.getIPv4(b.srcAddress)))+".\n"+
            "bacapp.unconfirmed_service==2 && bacapp.instance_number=="+b.instance+" && bacapp.instance_number=="+b.objectNumber+" && bacapp.objectType=="+b.objectType,
            notify
          ));
        }
      }
    });
  }
}