package aces.webctrl.wireshark.web;
import aces.webctrl.wireshark.core.*;
import javax.servlet.http.*;
import java.io.*;
public class StatPage extends ServletBase {
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String type = req.getParameter("type");
    if (type==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req));
    }else{
      switch (type){
        case "refresh":{
          res.setContentType("application/json");
          final PrintWriter w = res.getWriter();
          w.write("{\"lines\":");
          SavedData.writeStats(w);
          final StatPoint sp = SavedData.getLatestStats();
          final double total = sp==null?0:sp.whoIs+sp.whoHas+sp.whoIsRouter+sp.iAm+sp.iHave+sp.iAmRouter+sp.unconfirmedCOV+sp.other;
          final double duration = sp==null?0:(sp.end-sp.start)/1000.0;
          w.write(",\"latest\":{");
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
          w.write("}}");
          break;
        }
        default:{
          res.sendError(400, "Unrecognized type parameter.");
        }
      }
    }
  }
}