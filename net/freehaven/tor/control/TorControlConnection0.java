// $Id$
// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package net.freehaven.tor.control;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/** DOCDOC */
public class TorControlConnection0 extends TorControlConnection
    implements TorControlCommands
{
    protected java.io.DataOutputStream outStream;
    protected java.io.DataInputStream inStream;

    static class Cmd {
        public int type;
        public byte[] body;

        Cmd(int t, byte[] b) { type = t; body = b; }
        Cmd(int t, int l) { type = t; body = new byte[l]; };
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * a given socket.  After calling this constructor, it is typical to
     * call launchThread and authenticate. */
    public TorControlConnection0(java.net.Socket connection)
        throws IOException {
        this(connection.getInputStream(), connection.getOutputStream());
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * an arbitrary pair of data streams.
     */
    public TorControlConnection0(java.io.InputStream i, java.io.OutputStream o)
        throws IOException {
        this.outStream = new java.io.DataOutputStream(o);
        this.inStream = new java.io.DataInputStream(i);
        this.waiters = new LinkedList();
    }

    /** helper: sends a single (unfragmentable) command to Tor */
    protected final void sendCommand0(int type, byte[] cmd)
        throws IOException {
        int length = cmd == null ? 0 : cmd.length;
        outStream.writeShort((short)length);
        outStream.writeShort(type);
        if (cmd != null)
            outStream.write(cmd);
    }

    /** helper: sends a single (possibly fragmented) command to Tor */
    protected void sendCommand(short type, byte[] cmd) throws IOException {
        synchronized(this.outStream) {
            if (cmd == null || cmd.length <= 65535) {
                sendCommand0(type, cmd);
                return;
            }
            int length = cmd.length;
            outStream.writeShort(65535);
            outStream.writeShort(CMD_FRAGMENTHEADER);
            outStream.writeShort(type);
            outStream.writeInt(length);
            outStream.write(cmd, 0, 65535);
            for (int pos=65535; pos < length; pos += 65535) {
                int flen = length-pos < 65535 ? length-pos : 65535;
                outStream.writeShort(flen);
                outStream.writeShort(CMD_FRAGMENT);
                this.outStream.write(cmd, pos, flen);
            }
        }
    }

    /** helper: read a possibly fragmented command from Tor */
    protected final Cmd readCommand0() throws IOException {
        int len = this.inStream.readUnsignedShort();
        int cmd = this.inStream.readUnsignedShort();
        byte[] result = new byte[len];
        this.inStream.readFully(result);
        return new Cmd(cmd, result);
    }

    /** Read a command from Tor, defragmenting as necessary */
    protected Cmd readCommand() throws IOException {
        synchronized (inStream) {
            Cmd c = readCommand0();
            if (c.type != CMD_FRAGMENT && c.type != CMD_FRAGMENTHEADER)
                return c;

            if (c.type == CMD_FRAGMENT)
                throw new TorControlSyntaxError("Fragment without header");

            int realType = Bytes.getU16(c.body, 0);
            int realLen = Bytes.getU32(c.body, 2);

            Cmd out = new Cmd(realType, realLen);
            System.arraycopy(c.body, 6, out.body, 0, c.body.length-6);
            int pos = c.body.length-6;
            while (pos < realLen) {
                c = readCommand0();
                if (c.type != CMD_FRAGMENT)
                    throw new TorControlSyntaxError("Incomplete fragmented message");
                System.arraycopy(c.body, 0, out.body, pos, c.body.length);
                pos += c.body.length;
            }
            return out;
        }
    }

    /** helper: implement the main background loop. */
    protected void react() throws IOException {
        while (true) {
            Cmd c = readCommand();
            if (c.type == CMD_EVENT)
                handleEvent(c);
            else {
                Waiter w;
                synchronized (waiters) {
                    w = (Waiter) waiters.removeFirst();
                }
                w.setResponse(c);
            }
        }
    }

    /** helper: Send a command and wait for the next reponse type command
     * to be received (in order) */
    protected synchronized Cmd _sendAndWaitForResponse(short type, byte[] cmd)
        throws IOException {
        checkThread();
        Waiter w = new Waiter();
        synchronized (waiters) {
            sendCommand(type, cmd);
            waiters.addLast(w);
        }
        return (Cmd) w.getResponse();
    }

    /** Send a message to Tor, and wait for a respose.
     *
     * @throw TorControlError if Tor tells us about an error
     * @throw TorControlSyntaxError if the response type wasn't exType1...4
     **/
    protected Cmd sendAndWaitForResponse(short type, byte[] cmd,
                   short exType1, short exType2, short exType3, short exType4)
        throws IOException {

        Cmd c = _sendAndWaitForResponse(type, cmd);
        if (c.type == CMD_ERROR)
            throw new TorControlError(Bytes.getU16(c.body, 0),
                                      Bytes.getNulTerminatedStr(c.body, 2));
        if (c.type == exType1 || c.type == exType2 || c.type == exType3 ||
            c.type == exType4)
            return c;

        throw new TorControlSyntaxError("Unexpected reply type: "+c.type);
    }

    protected Cmd sendAndWaitForResponse(short type, byte[] cmd)
        throws IOException {
        return sendAndWaitForResponse(type, cmd, CMD_DONE, CMD_DONE, CMD_DONE, CMD_DONE);
    }

    protected Cmd sendAndWaitForResponse(short type, byte[] cmd, short exType1)
        throws IOException {
        return sendAndWaitForResponse(type, cmd, exType1, exType1, exType1,
                                      exType1);
    }

    protected Cmd sendAndWaitForResponse(short type, byte[] cmd,
                                    short exType1, short exType2)
        throws IOException {
        return sendAndWaitForResponse(type, cmd, exType1, exType2, exType2,
                                      exType2);
    }

    protected Cmd sendAndWaitForResponse(short type, byte[] cmd,
                                   short exType1, short exType2, short exType3)
        throws IOException {
        return sendAndWaitForResponse(type, cmd, exType1, exType2, exType3,
                                      exType3);
    }

    /** Helper: decode a CMD_EVENT command and dispatch it to our
     * EventHandler (if any). */
    protected void handleEvent(Cmd c) {
        if (handler == null)
            return;
        int type = Bytes.getU16(c.body, 0);

        switch (type) {
          case EVENT_CIRCSTATUS:
              handler.circuitStatus(CIRC_STATUS_NAMES[c.body[2]],
                                    Bytes.getU32S(c.body, 3),
                                    Bytes.getNulTerminatedStr(c.body, 7));
              break;
          case EVENT_STREAMSTATUS:
              handler.streamStatus(STREAM_STATUS_NAMES[c.body[2]],
                                   Bytes.getU32S(c.body, 3),
                                   Bytes.getNulTerminatedStr(c.body, 7));
              break;
          case EVENT_ORCONNSTATUS:
              handler.orConnStatus(OR_CONN_STATUS_NAMES[c.body[2]],
                                   Bytes.getNulTerminatedStr(c.body, 3));
              break;
          case EVENT_BANDWIDTH:
              handler.bandwidthUsed(Bytes.getU32(c.body, 2),
                                    Bytes.getU32(c.body, 6));
              break;
          case EVENT_NEWDESCRIPTOR:
              List lst = new ArrayList();
              Bytes.splitStr(lst, c.body, 2, (byte)',');
              handler.newDescriptors(lst);
              break;
          case EVENT_MSG_DEBUG:
              handler.message("DEBUG", Bytes.getNulTerminatedStr(c.body, 2));
              break;
          case EVENT_MSG_INFO:
              handler.message("INFO", Bytes.getNulTerminatedStr(c.body, 2));
              break;
          case EVENT_MSG_NOTICE:
              handler.message("NOTICE", Bytes.getNulTerminatedStr(c.body, 2));
              break;
          case EVENT_MSG_WARN:
              handler.message("WARN", Bytes.getNulTerminatedStr(c.body, 2));
              break;
          case EVENT_MSG_ERROR:
              handler.message("ERR", Bytes.getNulTerminatedStr(c.body, 2));
              break;
          default:
              throw new TorControlSyntaxError("Unrecognized event type.");
        }
    }

    /** Change the values of the configuration options stored in
     * 'kvList'.  (The format is "key value"). */
    public void setConf(Collection kvList) throws IOException {
        StringBuffer b = new StringBuffer();
        for (Iterator it = kvList.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            b.append(kv).append("\n");
        }
        sendAndWaitForResponse(CMD_SETCONF, b.toString().getBytes());
    }

    public List getConf(Collection keys) throws IOException {
        StringBuffer s = new StringBuffer();
        for (Iterator it = keys.iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            s.append(key).append("\n");
        }
        Cmd c = sendAndWaitForResponse(CMD_GETCONF, s.toString().getBytes(),
                                       CMD_CONFVALUE);
        List lines = new ArrayList();
        Bytes.splitStr(lines, c.body, 0, (byte)'\n');
        List result = new ArrayList();
        for (Iterator it = lines.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            int idx = kv.indexOf(' ');
            result.add(new ConfigEntry(kv.substring(0, idx),
                                       kv.substring(idx+1)));
        }
        return result;
    }

    public void setEvents(List events) throws IOException {
        byte[] ba = new byte[events.size() * 2];
        int i;
        Iterator it;
        for(i=0, it = events.iterator(); it.hasNext(); i += 2) {
            Object event = it.next();
            short e = -1;
            if (event instanceof Number) {
                e = ((Number)event).shortValue();
            } else {
                String s = ((String) event).toUpperCase();
                for (int j = 0; i < EVENT_NAMES.length; ++i) {
                    if (EVENT_NAMES[j].equals(s)) {
                        e = (short)j;
                        break;
                    }
                }
                if (e < 0)
                    throw new Error("Unknown v0 code for event '"+s+"'");
            }
            Bytes.setU16(ba, i, e);
        }
        sendAndWaitForResponse(CMD_SETEVENTS, ba);
        System.out.println("OK");
    }

    public void authenticate(byte[] auth) throws IOException {
        if (auth == null)
            auth = new byte[0];
        sendAndWaitForResponse(CMD_AUTH, auth);
    }

    public void saveConf() throws IOException {
        sendAndWaitForResponse(CMD_SAVECONF, new byte[0]);
    }

    public void signal(String signal) throws IOException {
        int sig;
        signal = signal.toUpperCase();
        if (signal.equals("HUP") || signal.equals("RELOAD"))
            sig = SIGNAL_HUP;
        else if (signal.equals("INT") || signal.equals("SHUTDOWN"))
            sig = SIGNAL_HUP;
        else if (signal.equals("USR1") || signal.equals("DUMP"))
            sig = SIGNAL_HUP;
        else if (signal.equals("USR2") || signal.equals("DEBUG"))
            sig = SIGNAL_HUP;
        else if (signal.equals("TERM") || signal.equals("HALT"))
            sig = SIGNAL_HUP;
        else
            throw new Error("Unrecognized value for signal()");
        byte[] ba = { (byte)sig };
        sendAndWaitForResponse(CMD_SIGNAL, ba);
    }

    public Map mapAddresses(Collection kvLines) throws IOException {
        StringBuffer sb = new StringBuffer();
        for (Iterator it = kvLines.iterator(); it.hasNext(); ) {
            sb.append((String)it.next()).append("\n");
        }
        Cmd c = sendAndWaitForResponse(CMD_MAPADDRESS, sb.toString().getBytes());
        Map result = new HashMap();
        List lst = new ArrayList();
        Bytes.splitStr(lst, c.body, 0, (byte)'\n');
        for (Iterator it = lst.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            int idx = kv.indexOf(' ');
            result.put(kv.substring(0, idx),
                       kv.substring(idx+1));
        }
        return result;
    }

    public Map getInfo(Collection keys) throws IOException {
        StringBuffer sb = new StringBuffer();
        for (Iterator it = keys.iterator(); it.hasNext(); ) {
            sb.append(((String)it.next())+"\n");
        }
        Cmd c = sendAndWaitForResponse(CMD_GETINFO, sb.toString().getBytes(),
                                       CMD_INFOVALUE);
        Map m = new HashMap();
        List lst = new ArrayList();
        Bytes.splitStr(lst, c.body, 0, (byte)0);
        if ((lst.size() % 2) != 0)
            throw new TorControlSyntaxError(
                                     "Odd number of substrings from GETINFO");
        for (Iterator it = lst.iterator(); it.hasNext(); ) {
            Object k = it.next();
            Object v = it.next();
            m.put(k, v);
        }
        return m;
    }

    public String extendCircuit(String circID, String path) throws IOException {
        byte[] p = path.getBytes();
        byte[] ba = new byte[p.length+4];
        Bytes.setU32(ba, 0, (int)Long.parseLong(circID));
        System.arraycopy(p, 0, ba, 4, p.length);
        Cmd c = sendAndWaitForResponse(CMD_EXTENDCIRCUIT, ba);
        return Integer.toString(Bytes.getU32(c.body, 0));
    }

    public void attachStream(String streamID, String circID)
        throws IOException {
        byte[] ba = new byte[8];
        Bytes.setU32(ba, 0, (int)Long.parseLong(streamID));
        Bytes.setU32(ba, 4, (int)Long.parseLong(circID));
        sendAndWaitForResponse(CMD_ATTACHSTREAM, ba);
    }

    /** Tell Tor about the server descriptor in 'desc' */
    public String postDescriptor(String desc) throws IOException {
        return new String(
             sendAndWaitForResponse(CMD_POSTDESCRIPTOR, desc.getBytes()).body);
    }

    /** Tell Tor to change the target of the stream identified by 'streamID'
     * to 'address'.
     */
    public void redirectStream(String streamID, String address) throws IOException {
        byte[] addr = address.getBytes();
        byte[] ba = new byte[addr.length+4];
        Bytes.setU32(ba, 0, (int)Long.parseLong(streamID));
        System.arraycopy(addr, 0, ba, 4, addr.length);
        sendAndWaitForResponse(CMD_REDIRECTSTREAM, ba);
    }

    /** Tell Tor to close the stream identified by 'streamID'.
     */
    public void closeStream(String streamID, byte reason)
        throws IOException {
        byte[] ba = new byte[6];
        Bytes.setU32(ba, 0, (int)Long.parseLong(streamID));
        ba[4] = reason;
        ba[5] = (byte)0;
        sendAndWaitForResponse(CMD_CLOSESTREAM, ba);
    }

    /** Tell Tor to close the circuit identified by 'streamID'.
     */
    public void closeCircuit(String circID, boolean ifUnused) throws IOException {
        byte[] ba = new byte[5];
        Bytes.setU32(ba, 0, (int)Long.parseLong(circID));
        ba[4] = (byte)(ifUnused? 1 : 0);
        sendAndWaitForResponse(CMD_CLOSECIRCUIT, ba);
    }

}

