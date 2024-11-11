package aces.webctrl.wireshark.web;
import aces.webctrl.wireshark.core.*;
import javax.servlet.http.*;
import javax.servlet.annotation.MultipartConfig;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.regex.*;
import java.util.stream.Stream;
import java.util.function.Consumer;
@MultipartConfig
public class MainPage extends ServletBase {
  private final static Pattern splitter = Pattern.compile(";", Pattern.LITERAL);
  /**
   * {@inheritDoc}
   */
  @Override public String getHTML(final HttpServletRequest req) throws Throwable {
    if (html==null){
      super.getHTML(req);
      html = html
        .replace("__fdru_DEFAULT__",String.valueOf(PacketAlarm._MAX_RESPONSE_TIME))
        .replace("__eot_DEFAULT__",String.valueOf(PacketAlarm._EXCESS_OTHER_TRAFFIC))
        .replace("__ias_DEFAULT__",String.valueOf(PacketAlarm._I_AM_SPAM))
        .replace("__wis_DEFAULT__",String.valueOf(PacketAlarm._WHO_IS_SPAM))
        .replace("__uwi_DEFAULT__",String.valueOf(PacketAlarm._UNANSWERED_WHO_IS))
        .replace("__din_DEFAULT__",String.valueOf(PacketAlarm._DUPLICATE_INSTANCE_NUMBER))
        .replace("__iad_DEFAULT__",String.valueOf(PacketAlarm._I_AM_DOUBLING))
        .replace("__iasl_DEFAULT__",String.valueOf(PacketAlarm._I_AM_SLOW))
        .replace("__iars_DEFAULT__",String.valueOf(PacketAlarm._I_AM_ROUTER_SPAM))
        .replace("__wirs_DEFAULT__",String.valueOf(PacketAlarm._WHO_IS_ROUTER_SPAM))
        .replace("__uwir_DEFAULT__",String.valueOf(PacketAlarm._UNANSWERED_WHO_IS_ROUTER))
        .replace("__dnn_DEFAULT__",String.valueOf(PacketAlarm._DUPLICATE_NETWORK_NUMBER))
        .replace("__ihs_DEFAULT__",String.valueOf(PacketAlarm._I_HAVE_SPAM))
        .replace("__whs_DEFAULT__",String.valueOf(PacketAlarm._WHO_HAS_SPAM))
        .replace("__uwh_DEFAULT__",String.valueOf(PacketAlarm._UNANSWERED_WHO_HAS))
        .replace("__ucs_DEFAULT__",String.valueOf(PacketAlarm._UNCONFIRMED_COV_SPAM));
    }
    return super.getHTML(req);
  }
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String type = req.getParameter("type");
    if (type==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req));
    }else{
      switch (type){
        case "save":{
          final String capDir = req.getParameter("capDir");
          final String emailSubject = req.getParameter("emailSubject");
          final String emailRecipients = req.getParameter("emailRecipients");
          final String fdru = req.getParameter("fdru");
          final String eot = req.getParameter("eot");
          final String ias = req.getParameter("ias");
          final String wis = req.getParameter("wis");
          final String uwi = req.getParameter("uwi");
          final String din = req.getParameter("din");
          final String iad = req.getParameter("iad");
          final String iasl = req.getParameter("iasl");
          final String iars = req.getParameter("iars");
          final String wirs = req.getParameter("wirs");
          final String uwir = req.getParameter("uwir");
          final String dnn = req.getParameter("dnn");
          final String ihs = req.getParameter("ihs");
          final String whs = req.getParameter("whs");
          final String uwh = req.getParameter("uwh");
          final String ucs = req.getParameter("ucs");
          final String _fdru = req.getParameter("_fdru");
          final String _eot = req.getParameter("_eot");
          final String _rbtn = req.getParameter("_rbtn");
          final String _ias = req.getParameter("_ias");
          final String _wis = req.getParameter("_wis");
          final String _uwi = req.getParameter("_uwi");
          final String _din = req.getParameter("_din");
          final String _iad = req.getParameter("_iad");
          final String _iasl = req.getParameter("_iasl");
          final String _iars = req.getParameter("_iars");
          final String _wirs = req.getParameter("_wirs");
          final String _uwir = req.getParameter("_uwir");
          final String _dnn = req.getParameter("_dnn");
          final String _ihs = req.getParameter("_ihs");
          final String _whs = req.getParameter("_whs");
          final String _uwh = req.getParameter("_uwh");
          final String _ucs = req.getParameter("_ucs");
          boolean bad = false;
          bad|=capDir==null;
          bad|=emailSubject==null;
          bad|=emailRecipients==null;
          bad|=fdru==null;
          bad|=eot==null;
          bad|=ias==null;
          bad|=wis==null;
          bad|=uwi==null;
          bad|=din==null;
          bad|=iad==null;
          bad|=iasl==null;
          bad|=iars==null;
          bad|=wirs==null;
          bad|=uwir==null;
          bad|=dnn==null;
          bad|=ihs==null;
          bad|=whs==null;
          bad|=uwh==null;
          bad|=ucs==null;
          bad|=_fdru==null;
          bad|=_eot==null;
          bad|=_rbtn==null;
          bad|=_ias==null;
          bad|=_wis==null;
          bad|=_uwi==null;
          bad|=_din==null;
          bad|=_iad==null;
          bad|=_iasl==null;
          bad|=_iars==null;
          bad|=_wirs==null;
          bad|=_uwir==null;
          bad|=_dnn==null;
          bad|=_ihs==null;
          bad|=_whs==null;
          bad|=_uwh==null;
          bad|=_ucs==null;
          if (bad){
            res.setStatus(400);
            return;
          }
          try{
            long alarmFlags = 0;
            if (Boolean.parseBoolean(_fdru)){ alarmFlags|=PacketAlarm.FDR_UNNECESSARY; }
            if (Boolean.parseBoolean(_eot)){ alarmFlags|=PacketAlarm.EXCESS_OTHER_TRAFFIC; }
            if (Boolean.parseBoolean(_rbtn)){ alarmFlags|=PacketAlarm.ROUTER_BUSY_TO_NETWORK; }
            if (Boolean.parseBoolean(_ias)){ alarmFlags|=PacketAlarm.I_AM_SPAM; }
            if (Boolean.parseBoolean(_wis)){ alarmFlags|=PacketAlarm.WHO_IS_SPAM; }
            if (Boolean.parseBoolean(_uwi)){ alarmFlags|=PacketAlarm.UNANSWERED_WHO_IS; }
            if (Boolean.parseBoolean(_din)){ alarmFlags|=PacketAlarm.DUPLICATE_INSTANCE_NUMBER; }
            if (Boolean.parseBoolean(_iad)){ alarmFlags|=PacketAlarm.I_AM_DOUBLING; }
            if (Boolean.parseBoolean(_iasl)){ alarmFlags|=PacketAlarm.I_AM_SLOW; }
            if (Boolean.parseBoolean(_iars)){ alarmFlags|=PacketAlarm.I_AM_ROUTER_SPAM; }
            if (Boolean.parseBoolean(_wirs)){ alarmFlags|=PacketAlarm.WHO_IS_ROUTER_SPAM; }
            if (Boolean.parseBoolean(_uwir)){ alarmFlags|=PacketAlarm.UNANSWERED_WHO_IS_ROUTER; }
            if (Boolean.parseBoolean(_dnn)){ alarmFlags|=PacketAlarm.DUPLICATE_NETWORK_NUMBER; }
            if (Boolean.parseBoolean(_ihs)){ alarmFlags|=PacketAlarm.I_HAVE_SPAM; }
            if (Boolean.parseBoolean(_whs)){ alarmFlags|=PacketAlarm.WHO_HAS_SPAM; }
            if (Boolean.parseBoolean(_uwh)){ alarmFlags|=PacketAlarm.UNANSWERED_WHO_HAS; }
            if (Boolean.parseBoolean(_ucs)){ alarmFlags|=PacketAlarm.UNCONFIRMED_COV_SPAM; }
            final int fdru_ = Integer.parseInt(fdru);
            final int eot_ = Integer.parseInt(eot);
            final int ias_ = Integer.parseInt(ias);
            final int wis_ = Integer.parseInt(wis);
            final int uwi_ = Integer.parseInt(uwi);
            final int din_ = Integer.parseInt(din);
            final double iad_ = Double.parseDouble(iad);
            final int iasl_ = Integer.parseInt(iasl);
            final int iars_ = Integer.parseInt(iars);
            final int wirs_ = Integer.parseInt(wirs);
            final int uwir_ = Integer.parseInt(uwir);
            final int dnn_ = Integer.parseInt(dnn);
            final int ihs_ = Integer.parseInt(ihs);
            final int whs_ = Integer.parseInt(whs);
            final int uwh_ = Integer.parseInt(uwh);
            final int ucs_ = Integer.parseInt(ucs);
            SavedData.emailRecipients = splitter.split(emailRecipients);
            SavedData.emailSubject = emailSubject;
            SavedData.setCaptureDir(capDir);
            SavedData.alarmFlags = alarmFlags;
            SavedData._MAX_RESPONSE_TIME = fdru_;
            SavedData._EXCESS_OTHER_TRAFFIC = eot_;
            SavedData._I_AM_SPAM = ias_;
            SavedData._WHO_IS_SPAM = wis_;
            SavedData._UNANSWERED_WHO_IS = uwi_;
            SavedData._DUPLICATE_INSTANCE_NUMBER = din_;
            SavedData._I_AM_DOUBLING = iad_;
            SavedData._I_AM_SLOW = iasl_;
            SavedData._I_AM_ROUTER_SPAM = iars_;
            SavedData._WHO_IS_ROUTER_SPAM = wirs_;
            SavedData._UNANSWERED_WHO_IS_ROUTER = uwir_;
            SavedData._DUPLICATE_NETWORK_NUMBER = dnn_;
            SavedData._I_HAVE_SPAM = ihs_;
            SavedData._WHO_HAS_SPAM = whs_;
            SavedData._UNANSWERED_WHO_HAS = uwh_;
            SavedData._UNCONFIRMED_COV_SPAM = ucs_;
          }catch(Throwable t){
            res.setStatus(400);
            return;
          }
          SavedData.saveData();
          break;
        }
        case "refresh":{
          final StatPoint sp = SavedData.getLatestStats();
          final double total = sp==null?0:sp.whoIs+sp.whoHas+sp.whoIsRouter+sp.iAm+sp.iHave+sp.iAmRouter+sp.unconfirmedCOV+sp.other;
          final double duration = sp==null?0:(sp.end-sp.start)/1000.0;
          res.setContentType("application/json");
          final PrintWriter w = res.getWriter();
          w.write("{");
          w.write("\"capDir\":\"");w.write(Utility.escapeJSON(SavedData.captureDir_));w.write("\",");
          w.write("\"emailSubject\":\"");w.write(Utility.escapeJSON(SavedData.emailSubject));w.write("\",");
          w.write("\"emailRecipients\":\"");w.write(Utility.escapeJSON(String.join(";", SavedData.emailRecipients)));w.write("\",");
          w.write("\"firstCheck\":");w.write(sp==null?"0":String.valueOf(sp.start/1000));w.write(",");
          w.write("\"lastCheck\":");w.write(sp==null?"0":String.valueOf(sp.end/1000));w.write(",");
          w.write("\"alarmCount\":\"");w.write(String.valueOf(SavedData.alarms.size()));w.write("\",");
          w.write("\"ram\":\"");w.write(PacketAnalysis.df.format(Initializer.estimateRAM()/1048576.0)+" MB");w.write("\",");
          w.write("\"fdru\":\"");w.write(String.valueOf(SavedData._MAX_RESPONSE_TIME));w.write("\",");
          w.write("\"eot\":\"");w.write(String.valueOf(SavedData._EXCESS_OTHER_TRAFFIC));w.write("\",");
          w.write("\"ias\":\"");w.write(String.valueOf(SavedData._I_AM_SPAM));w.write("\",");
          w.write("\"wis\":\"");w.write(String.valueOf(SavedData._WHO_IS_SPAM));w.write("\",");
          w.write("\"uwi\":\"");w.write(String.valueOf(SavedData._UNANSWERED_WHO_IS));w.write("\",");
          w.write("\"din\":\"");w.write(String.valueOf(SavedData._DUPLICATE_INSTANCE_NUMBER));w.write("\",");
          w.write("\"iad\":\"");w.write(PacketAnalysis.df.format(SavedData._I_AM_DOUBLING));w.write("\",");
          w.write("\"iasl\":\"");w.write(String.valueOf(SavedData._I_AM_SLOW));w.write("\",");
          w.write("\"iars\":\"");w.write(String.valueOf(SavedData._I_AM_ROUTER_SPAM));w.write("\",");
          w.write("\"wirs\":\"");w.write(String.valueOf(SavedData._WHO_IS_ROUTER_SPAM));w.write("\",");
          w.write("\"uwir\":\"");w.write(String.valueOf(SavedData._UNANSWERED_WHO_IS_ROUTER));w.write("\",");
          w.write("\"dnn\":\"");w.write(String.valueOf(SavedData._DUPLICATE_NETWORK_NUMBER));w.write("\",");
          w.write("\"ihs\":\"");w.write(String.valueOf(SavedData._I_HAVE_SPAM));w.write("\",");
          w.write("\"whs\":\"");w.write(String.valueOf(SavedData._WHO_HAS_SPAM));w.write("\",");
          w.write("\"uwh\":\"");w.write(String.valueOf(SavedData._UNANSWERED_WHO_HAS));w.write("\",");
          w.write("\"ucs\":\"");w.write(String.valueOf(SavedData._UNCONFIRMED_COV_SPAM));w.write("\",");
          w.write("\"_fdru\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.FDR_UNNECESSARY)!=0L));w.write(",");
          w.write("\"_eot\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.EXCESS_OTHER_TRAFFIC)!=0L));w.write(",");
          w.write("\"_rbtn\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.ROUTER_BUSY_TO_NETWORK)!=0L));w.write(",");
          w.write("\"_ias\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.I_AM_SPAM)!=0L));w.write(",");
          w.write("\"_wis\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.WHO_IS_SPAM)!=0L));w.write(",");
          w.write("\"_uwi\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.UNANSWERED_WHO_IS)!=0L));w.write(",");
          w.write("\"_din\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.DUPLICATE_INSTANCE_NUMBER)!=0L));w.write(",");
          w.write("\"_iad\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.I_AM_DOUBLING)!=0L));w.write(",");
          w.write("\"_iasl\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.I_AM_SLOW)!=0L));w.write(",");
          w.write("\"_iars\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.I_AM_ROUTER_SPAM)!=0L));w.write(",");
          w.write("\"_wirs\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.WHO_IS_ROUTER_SPAM)!=0L));w.write(",");
          w.write("\"_uwir\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.UNANSWERED_WHO_IS_ROUTER)!=0L));w.write(",");
          w.write("\"_dnn\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.DUPLICATE_NETWORK_NUMBER)!=0L));w.write(",");
          w.write("\"_ihs\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.I_HAVE_SPAM)!=0L));w.write(",");
          w.write("\"_whs\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.WHO_HAS_SPAM)!=0L));w.write(",");
          w.write("\"_uwh\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.UNANSWERED_WHO_HAS)!=0L));w.write(",");
          w.write("\"_ucs\":");w.write(String.valueOf((SavedData.alarmFlags&PacketAlarm.UNCONFIRMED_COV_SPAM)!=0L));w.write(",");
          w.write("\"rel_ucov\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.unconfirmedCOV/total*100));w.write("%\",");
          w.write("\"rel_wi\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.whoIs/total*100));w.write("%\",");
          w.write("\"rel_ia\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.iAm/total*100));w.write("%\",");
          w.write("\"rel_wh\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.whoHas/total*100));w.write("%\",");
          w.write("\"rel_ih\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.iHave/total*100));w.write("%\",");
          w.write("\"rel_wir\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.whoIsRouter/total*100));w.write("%\",");
          w.write("\"rel_iar\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.iAmRouter/total*100));w.write("%\",");
          w.write("\"rel_o\":\"");w.write(total<=0?"-":PacketAnalysis.df.format(sp.other/total*100));w.write("%\",");
          w.write("\"pps_ucov\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.unconfirmedCOV/duration));w.write("\",");
          w.write("\"pps_wi\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.whoIs/duration));w.write("\",");
          w.write("\"pps_ia\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.iAm/duration));w.write("\",");
          w.write("\"pps_wh\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.whoHas/duration));w.write("\",");
          w.write("\"pps_ih\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.iHave/duration));w.write("\",");
          w.write("\"pps_wir\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.whoIsRouter/duration));w.write("\",");
          w.write("\"pps_iar\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.iAmRouter/duration));w.write("\",");
          w.write("\"pps_o\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(sp.other/duration));w.write("\",");
          w.write("\"pps_tot\":\"");w.write(duration<=0?"-":PacketAnalysis.df.format(total/duration));w.write("\",");
          w.write("\"spp_ucov\":\"");w.write(duration<=0 || sp.unconfirmedCOV<=0?"-":PacketAnalysis.df.format(duration/sp.unconfirmedCOV));w.write("\",");
          w.write("\"spp_wi\":\"");w.write(duration<=0 || sp.whoIs<=0?"-":PacketAnalysis.df.format(duration/sp.whoIs));w.write("\",");
          w.write("\"spp_ia\":\"");w.write(duration<=0 || sp.iAm<=0?"-":PacketAnalysis.df.format(duration/sp.iAm));w.write("\",");
          w.write("\"spp_wh\":\"");w.write(duration<=0 || sp.whoHas<=0?"-":PacketAnalysis.df.format(duration/sp.whoHas));w.write("\",");
          w.write("\"spp_ih\":\"");w.write(duration<=0 || sp.iHave<=0?"-":PacketAnalysis.df.format(duration/sp.iHave));w.write("\",");
          w.write("\"spp_wir\":\"");w.write(duration<=0 || sp.whoIsRouter<=0?"-":PacketAnalysis.df.format(duration/sp.whoIsRouter));w.write("\",");
          w.write("\"spp_iar\":\"");w.write(duration<=0 || sp.iAmRouter<=0?"-":PacketAnalysis.df.format(duration/sp.iAmRouter));w.write("\",");
          w.write("\"spp_o\":\"");w.write(duration<=0 || sp.other<=0?"-":PacketAnalysis.df.format(duration/sp.other));w.write("\",");
          w.write("\"spp_tot\":\"");w.write(duration<=0 || total<=0?"-":PacketAnalysis.df.format(duration/total));w.write("\"");
          w.write("}");
          break;
        }
        case "download":{
          final Path dir = SavedData.captureDir;
          if (dir==null || !Files.exists(dir)){
            res.setStatus(500);
            return;
          }
          final Container<Long> max = new Container<Long>(0L);
          final Container<Path> f = new Container<Path>();
          try(
            Stream<Path> s = Files.list(dir);
          ){
            s.forEach(new Consumer<Path>(){
              @Override public void accept(Path p){
                try{
                  long l;
                  if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".pcap") && (l=Files.getLastModifiedTime(p).toMillis())>max.x){
                    max.x = l;
                    f.x = p;
                  }
                }catch(Throwable t){}
              }
            });
          }
          if (f.x==null){
            res.setStatus(500);
            return;
          }
          res.setContentType("application/octet-stream");
          res.setHeader("Content-Disposition","attachment;filename=\""+f.x.getFileName().toString()+"\"");
          ByteBuffer buf = ByteBuffer.allocate(8192);
          boolean go = true;
          try(
            WritableByteChannel out = Channels.newChannel(res.getOutputStream());
            FileChannel in = FileChannel.open(f.x, StandardOpenOption.READ);
          ){
            do {
              do {
                go = in.read(buf)!=-1;
              } while (go && buf.hasRemaining());
              buf.flip();
              while (buf.hasRemaining()){
                out.write(buf);
              }
              buf.clear();
            } while (go);
          }
          break;
        }
        case "trigger":{
          Initializer.trigger();
          break;
        }
        default:{
          res.sendError(400, "Unrecognized type parameter.");
        }
      }
    }
  }
}