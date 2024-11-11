package aces.webctrl.wireshark.web;
import aces.webctrl.wireshark.core.*;
import com.controlj.green.addonsupport.access.*;
import com.controlj.green.addonsupport.web.*;
import com.controlj.green.directaccess.*;
import com.controlj.green.core.data.*;
import javax.servlet.http.*;
import java.util.*;
import java.util.regex.*;
public class AlarmPage extends ServletBase {
  private final static Pattern resolver = Pattern.compile("((?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|\\d)){3})(?:\\)?+ on network (\\d++) with MAC (\\d++)(?!\\.\\d))?+");
  public static String getLink(final HttpServletRequest req, final CoreNode node) throws Throwable {
    final LocationReference lr = LocationReferenceFactory.fromNode(node);
    return DirectAccess.getDirectAccess().getRootSystemConnection().runReadAction(FieldAccessFactory.newDisabledFieldAccess(), new ReadActionResult<String>(){
      @Override public String execute(SystemAccess sys) throws Exception {
        return Link.createLink(UITree.NET, lr.resolve(sys), "properties", "default", "default", "view").getURL(req);
      }
    });
  }
  public static CoreNode recurse(final CoreNode router, final int network, final int mac) throws Throwable {
    // routers -> networks -> devices,routers
    // router nodes: node-type=233
    // network nodes: node-type=202,network-number=#
    // device nodes: node-type=204,mac-address=#
    final List<CoreNode> networks = router.getChildrenByType((short)202);
    for (CoreNode net: networks){
      try{
        if (net.getIntAttribute(CoreNodeConstants.NETWORK_NUMBER)==network){
          for (CoreNode dev: net.getChildrenByType(new short[]{204,233})){
            try{
              if (dev.getIntAttribute(CoreNodeConstants.MAC_ADDRESS)==mac){
                return dev;
              }
            }catch(Throwable t){}
          }
          return net;
        }
      }catch(Throwable t){}
    }
    CoreNode c;
    for (CoreNode net: networks){
      try{
        for (CoreNode r: net.getChildrenByType((short)233)){
          try{
            c = recurse(r,network,mac);
            if (c!=null){
              return c;
            }
          }catch(Throwable t){}
        }
      }catch(Throwable t){}
    }
    return null;
  }
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String type = req.getParameter("type");
    if (type==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req));
    }else{
      switch (type){
        case "resolve":{
          final String id = req.getParameter("id");
          if (id==null){
            if (Initializer.VERBOSE){
              Initializer.log("400: id parameter missing");
            }
            res.setStatus(400);
            return;
          }
          PacketAlarm pa = null;
          synchronized (SavedData.alarms){
            pa = SavedData.alarms.get(id);
          }
          if (pa==null){
            if (Initializer.VERBOSE){
              Initializer.log("404: cannot find alarm with given id");
            }
            res.setStatus(404);
            return;
          }
          final String alarmID = pa.getIdentifier();
          int i = alarmID.indexOf(':');
          final String cat = i==-1?alarmID:alarmID.substring(0,i);
          final String desc = pa.getDescription();
          pa = null;
          String url = null;
          switch (cat){
            case "EOT":{
              if (Initializer.VERBOSE){
                Initializer.log("404: no link can be given for EOT alarms");
              }
              res.setStatus(404);
              return;
            }
            case "FDRU":{
              url = Link.createLink(UITree.CFG, "/trees/config/connections", "properties", "default", "default", "config").getURL(req);
              break;
            }
            default:{
              TreeMap<Integer,Router> routers = Initializer.cache.routers;
              if (routers==null){
                if (Initializer.VERBOSE){
                  Initializer.log("404: routers are not loaded into memory");
                }
                res.setStatus(404);
                return;
              }
              final Matcher m = resolver.matcher(desc);
              if (!m.find()){
                if (Initializer.VERBOSE){
                  Initializer.log("404: regular expression does not match");
                }
                res.setStatus(404);
                return;
              }
              final Router r = routers.get(Utility.getAddressBits(m.group(1)));
              routers = null;
              if (r==null){
                if (Initializer.VERBOSE){
                  Initializer.log("404: cannot locate router with matched IP address");
                }
                res.setStatus(404);
                return;
              }
              String _network = m.group(2);
              String _mac = m.group(3);
              final int network = _network==null?-1:Integer.parseInt(_network);
              final int mac = _mac==null?-1:Integer.parseInt(_mac);
              try(
                DatabaseLink dl = new DatabaseLink(true);
              ){
                final CoreNode router = dl.getNode(r.getDBID());
                if (network==-1 || mac==-1){
                  url = getLink(req, router);
                  break;
                }
                CoreNode ret = recurse(router, network, mac);
                if (ret==null){
                  ret = router;
                }
                url = getLink(req, ret);
              }
            }
          }
          if (url==null){
            res.setStatus(404);
            return;
          }
          res.setContentType("text/plain");
          res.getWriter().print(url);
          break;
        }
        case "dismiss":{
          final String id = req.getParameter("id");
          if (id==null){
            res.setStatus(400);
            return;
          }
          PacketAlarm pa = null;
          synchronized (SavedData.alarms){
            pa = SavedData.alarms.get(id);
          }
          if (pa==null){
            res.setStatus(404);
            return;
          }
          pa.dismiss();
          break;
        }
        case "delete":{
          final String id = req.getParameter("id");
          if (id==null){
            res.setStatus(400);
            return;
          }
          PacketAlarm pa = null;
          synchronized (SavedData.alarms){
            pa = SavedData.alarms.remove(id);
          }
          if (pa==null){
            res.setStatus(404);
            return;
          }
          break;
        }
        case "reset":{
          PacketAlarm.clear();
          break;
        }
        case "refresh":{
          final StringBuilder sb = new StringBuilder(8192);
          sb.append('[');
          synchronized (SavedData.alarms){
            boolean first = true;
            for (PacketAlarm pa:SavedData.alarms.values()){
              if (first){
                first = false;
              }else{
                sb.append(',');
              }
              pa.toString(sb);
            }
          }
          sb.append(']');
          res.setContentType("application/json");
          res.getWriter().print(sb.toString());
          break;
        }
        default:{
          res.sendError(400, "Unrecognized type parameter.");
        }
      }
    }
  }
}