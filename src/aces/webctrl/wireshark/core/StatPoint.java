package aces.webctrl.wireshark.core;
import java.io.*;
/**
 * Stores a few basic statistics about a given packet capture.
 */
public class StatPoint implements Comparable<StatPoint> {
  /** The ending timestamp of the packet capture in epoch milliseconds. */
  public volatile long end;
  /** The starting timestamp of the packet capture in milliseconds. */
  public volatile long start;
  /** The number of Who-Is packets. */
  public volatile int whoIs;
  /** The number of I-Am packets. */
  public volatile int iAm;
  /** The number of Who-Is-Router packets. */
  public volatile int whoIsRouter;
  /** The number of I-Am-Router packets. */
  public volatile int iAmRouter;
  /** The number of Who-Has packets. */
  public volatile int whoHas;
  /** The number of I-Have packets. */
  public volatile int iHave;
  /** The number of Unconfirmed-COV packets. */
  public volatile int unconfirmedCOV;
  /** The number of broadcast packets which do not fit into another category listed here. */
  public volatile int other;
  /** Create a blank StatPoint for the purposes of deserialization. */
  private StatPoint(){}
  /** Create a new StatPoint. */
  public StatPoint(long start, long end){
    this.start = start;
    this.end = end;
    whoIs = 0;
    iAm = 0;
    whoIsRouter = 0;
    iAmRouter = 0;
    whoHas = 0;
    iHave = 0;
    unconfirmedCOV = 0;
    other = 0;
  }
  /**
   * Create an empty StatPoint for the purpose of performing a binary search.
   */
  public StatPoint(long time){
    this.end = time;
  }
  /**
   * Specifies a natural ordering by timestamp ascending.
   */
  @Override public int compareTo(StatPoint sp){
    return Long.compare(end, sp.end);
  }
  /**
   * Encodes the packet capture statistics as an JSON object written to the given PrintWriter.
   */
  public void toString(PrintWriter writer){
    writer.print('{');
    writer.print("\"start\":");writer.print(start/1000L);writer.print(',');
    writer.print("\"end\":");writer.print(end/1000L);writer.print(',');
    writer.print("\"ucov\":");writer.print(unconfirmedCOV);writer.print(',');
    writer.print("\"wi\":");writer.print(whoIs);writer.print(',');
    writer.print("\"ia\":");writer.print(iAm);writer.print(',');
    writer.print("\"wh\":");writer.print(whoHas);writer.print(',');
    writer.print("\"ih\":");writer.print(iHave);writer.print(',');
    writer.print("\"wir\":");writer.print(whoIsRouter);writer.print(',');
    writer.print("\"iar\":");writer.print(iAmRouter);writer.print(',');
    writer.print("\"o\":");writer.print(other);writer.print(',');
    writer.print("\"tot\":");writer.print(whoIs+whoHas+whoIsRouter+iAm+iHave+iAmRouter+unconfirmedCOV+other);
    writer.print('}');
  }
  /**
   * Writes the data in this object to the given SerializationStream.
   */
  public void serialize(SerializationStream s){
    s.write(end);
    s.write(start);
    s.write(whoIs);
    s.write(iAm);
    s.write(whoIsRouter);
    s.write(iAmRouter);
    s.write(whoHas);
    s.write(iHave);
    s.write(unconfirmedCOV);
    s.write(other);
  }
  /**
   * Retrieves a StatPoint from the given SerializationStream.
   */
  public static StatPoint deserialize(SerializationStream s){
    final StatPoint a = new StatPoint();
    a.end = s.readLong();
    a.start = s.readLong();
    a.whoIs = s.readInt();
    a.iAm = s.readInt();
    a.whoIsRouter = s.readInt();
    a.iAmRouter = s.readInt();
    a.whoHas = s.readInt();
    a.iHave = s.readInt();
    a.unconfirmedCOV = s.readInt();
    a.other = s.readInt();
    return a;
  }
}