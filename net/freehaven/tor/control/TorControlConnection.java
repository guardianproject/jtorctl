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

/** A connection to a running Tor process. */
public class TorControlConnection implements TorControlCommands {
    protected java.io.DataOutputStream outStream;
    protected java.io.DataInputStream inStream;
    protected EventHandler handler;

    protected LinkedList waiters;

    static class Waiter {
        Cmd response;
        public synchronized Cmd getResponse() {
            try {
                while (response == null) {
                    wait();
                }
            } catch (InterruptedException ex) {
                return null;
            }
            return response;
        }
        public synchronized void setResponse(Cmd response) {
            this.response = response;
            notifyAll();
        }
    }

    static class Cmd {
        public int type;
        public byte[] body;

        Cmd(int t, byte[] b) { type = t; body = b; }
        Cmd(int t, int l) { type = t; body = new byte[l]; };
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * a given socket.  After calling this constructor, it is typical to
     * call launchThread and authenticate. */
    public TorControlConnection(java.net.Socket connection) throws IOException {
        this(connection.getInputStream(), connection.getOutputStream());
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * an arbitrary pair of data streams.
     */
    public TorControlConnection(java.io.InputStream i, java.io.OutputStream o)
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

    /** Set the EventHandler object that will be notified of any
     * events Tor delivers to this connection.  To make Tor send us
     * events, call listenForEvents(). */
    public void setEventHandler(EventHandler handler) {
        this.handler = handler;
    }

    /**
     * Start a thread to react to Tor's responses in the background.
     * This is necessary to handle asynchronous events and synchronous
     * responses that arrive independantly over the same socket.
     */
    public Thread launchThread(boolean daemon) {
        Thread th = new Thread() {
                public void run() {
                    try {
                        react();
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            };
        if (daemon)
            th.setDaemon(true);
        th.start();
        return th;
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
        Waiter w = new Waiter();
        synchronized (waiters) {
            sendCommand(type, cmd);
            waiters.addLast(w);
        }
        return w.getResponse();
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
              handler.circuitStatus(c.body[2],
                                    (int)Bytes.getU32(c.body, 3),
                                    Bytes.getNulTerminatedStr(c.body, 7));
              break;
          case EVENT_STREAMSTATUS:
              handler.streamStatus(c.body[2],
                                   (int)Bytes.getU32(c.body, 3),
                                   Bytes.getNulTerminatedStr(c.body, 7));
              break;
          case EVENT_ORCONNSTATUS:
              handler.orConnStatus(c.body[2],
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
          case EVENT_MSG_INFO:
          case EVENT_MSG_NOTICE:
          case EVENT_MSG_WARN:
          case EVENT_MSG_ERROR:
              handler.message(type, Bytes.getNulTerminatedStr(c.body, 2));
              break;
          default:
              throw new TorControlSyntaxError("Unrecognized event type.");
        }
    }

    /** Change the value of the configuration option 'key' to 'val'.
     */
    public void setConf(String key, String value) throws IOException {
        List lst = new ArrayList();
        lst.add(key+" "+value);
        setConf(lst);
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

    /** Change the values of the configuration options stored in kvMap. */
    public void setConf(Map kvMap) throws IOException {
        List lst = new ArrayList();
        for (Iterator it = kvMap.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry ent = (Map.Entry) it.next();
            lst.add(ent.getKey()+" "+ent.getValue()+"\n");
        }
        setConf(lst);
    }

    /** Return the value of the configuration option 'key' */
    public String getConf(String key) throws IOException {
        List lst = new ArrayList();
        lst.add(key);
        Map r = getConf(lst);
        return (String) r.get(key);
    }

    /** Return a key-value map for the configuration options in 'keys' */
    public Map getConf(Collection keys) throws IOException {
        StringBuffer s = new StringBuffer();
        for (Iterator it = keys.iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            s.append(key).append("\n");
        }
        Cmd c = sendAndWaitForResponse(CMD_GETCONF, s.toString().getBytes(),
                                       CMD_CONFVALUE);
        List lines = new ArrayList();
        Bytes.splitStr(lines, c.body, 0, (byte)'\n');
        Map result = new HashMap();
        for (Iterator it = lines.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            int idx = kv.indexOf(' ');
            result.put(kv.substring(0, idx),
                       kv.substring(idx+1));
        }
        return result;
    }

    /** Tell Tor to begin sending us events of the types listed in 'events'.
     * Elements must be one of the EVENT_* values from TorControlCommands */
    public void setEvents(List events) throws IOException {
        byte[] ba = new byte[events.size() * 2];
        int i;
        Iterator it;
        for(i=0, it = events.iterator(); it.hasNext(); i += 2) {
            short event = ((Number)it.next()).shortValue();
            Bytes.setU16(ba, i, event);
        }
        sendAndWaitForResponse(CMD_SETEVENTS, ba);
        System.out.println("OK");
    }

    /** Send Tor an authentication sequence 'auth' */
    // XXXX more info about how to set this up securely.
    public void authenticate(byte[] auth) throws IOException {
        if (auth == null)
            auth = new byte[0];
        sendAndWaitForResponse(CMD_AUTH, auth);
    }

    /** Tell Tor to save the value of its configuration to disk. */
    public void saveConf() throws IOException {
        sendAndWaitForResponse(CMD_SAVECONF, new byte[0]);
    }

    /** Send a signal to the Tor process. */
    public void signal(int signal) throws IOException {
        if (signal != SIGNAL_HUP && signal != SIGNAL_INT &&
            signal != SIGNAL_USR1 && signal != SIGNAL_USR2 &&
            signal != SIGNAL_TERM)
            throw new Error("Unrecognized value for signal()");
        byte[] ba = { (byte)signal };
        sendAndWaitForResponse(CMD_SIGNAL, ba);
    }

    /** Tell Tor to replace incoming addresses with those as listed in 'kvLines'.
     */
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
    public Map mapAddresses(Map addresses) throws IOException {
        List kvList = new ArrayList();
        for (Iterator it = addresses.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry e = (Map.Entry) it.next();
            kvList.add(e.getKey()+" "+e.getValue());
        }
        return mapAddresses(kvList);
    }
    public String mapAddress(String fromAddr, String toAddr) throws IOException {
        List lst = new ArrayList();
        lst.add(fromAddr+" "+toAddr+"\n");
        Map m = mapAddresses(lst);
        return (String) m.get(fromAddr);
    }

    /** Look up the information values listed in keys. */
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

    /** Return the value of the information field 'key' */
    public String getInfo(String key) throws IOException {
        List lst = new ArrayList();
        lst.add(key);
        Map m = getInfo(lst);
        return (String) m.get(key);
    }

    /**
     * Tell Tor to extend the circuit identified by 'circID' through the
     * servers named in the list 'path'.
     */
    public int extendCircuit(int circID, String path) throws IOException {
        byte[] p = path.getBytes();
        byte[] ba = new byte[p.length+4];
        Bytes.setU32(ba, 0, circID);
        System.arraycopy(p, 0, ba, 4, p.length);
        Cmd c = sendAndWaitForResponse(CMD_EXTENDCIRCUIT, ba);
        return Bytes.getU32(c.body, 0);
    }

    /**
     * Tell Tor to attach the stream identified by 'streamID' to the circuit
     * identified by 'circID'.
     */
    public void attachStream(int streamID, int circID) throws IOException {
        byte[] ba = new byte[8];
        Bytes.setU32(ba, 0, streamID);
        Bytes.setU32(ba, 4, circID);
        sendAndWaitForResponse(CMD_ATTACHSTREAM, ba);
    }

    /** Tell Tor about the server descriptor in 'desc' */
    public String postDescriptor(byte[] desc) throws IOException {
        return new String(
                 sendAndWaitForResponse(CMD_POSTDESCRIPTOR, desc).body);
    }

    /** Tell Tor to change the target of the stream identified by 'streamID'
     * to 'address'.
     */
    public void redirectStream(int streamID, String address) throws IOException {
        byte[] addr = address.getBytes();
        byte[] ba = new byte[addr.length+4];
        Bytes.setU32(ba, 0, streamID);
        System.arraycopy(addr, 0, ba, 4, addr.length);
        sendAndWaitForResponse(CMD_REDIRECTSTREAM, ba);
    }

    /** Tell Tor to close the stream identified by 'streamID'.
     */
    public void closeStream(int streamID, byte reason, byte flags)
        throws IOException {
        byte[] ba = new byte[6];
        Bytes.setU32(ba, 0, streamID);
        ba[4] = reason;
        ba[5] = flags;
        sendAndWaitForResponse(CMD_CLOSESTREAM, ba);
    }

    /** Tell Tor to close the circuit identified by 'streamID'.
     */
    public void closeCircuit(int circID, byte flags) throws IOException {
        byte[] ba = new byte[5];
        Bytes.setU32(ba, 0, circID);
        ba[4] = flags;
        sendAndWaitForResponse(CMD_CLOSECIRCUIT, ba);
    }


}