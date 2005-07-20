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
import java.util.StringTokenizer;

/** DOCDOC */
public class TorControlConnection1 extends TorControlConnection
    implements TorControlCommands
{
    protected java.io.BufferedReader input;
    protected java.io.Writer output;
    protected java.io.PrintWriter debugOutput;

    static class ReplyLine {
        public String status;
        public String msg;
        public String rest;

        ReplyLine(String status, String msg, String rest) {
            this.status = status; this.msg = msg; this.rest = rest;
        }
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * a given socket.  After calling this constructor, it is typical to
     * call launchThread and authenticate. */
    public TorControlConnection1(java.net.Socket connection)
        throws IOException {
        this(connection.getInputStream(), connection.getOutputStream());
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * an arbitrary pair of data streams.
     */
    public TorControlConnection1(java.io.InputStream i, java.io.OutputStream o)
        throws IOException {
        this(new java.io.InputStreamReader(i),
             new java.io.OutputStreamWriter(o));
    }

    public TorControlConnection1(java.io.Reader i, java.io.Writer o)
        throws IOException {
        this.output = o;
        if (i instanceof java.io.BufferedReader)
            this.input = (java.io.BufferedReader) i;
        else
            this.input = new java.io.BufferedReader(i);

        this.waiters = new LinkedList();
    }

    protected final void writeEscaped(String s) throws IOException {
        StringTokenizer st = new StringTokenizer(s, "\n");
        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            if (line.startsWith("."))
                line = "."+line;
            if (line.endsWith("\r"))
                line += "\n";
            else
                line += "\r\n";
            if (debugOutput != null)
                debugOutput.print(">> "+line);
            output.write(line);
        }
        output.write(".\r\n");
        if (debugOutput != null)
            debugOutput.print(">> .\n");
    }

    protected static final String quote(String s) {
        StringBuffer sb = new StringBuffer("\"");
        for (int i = 0; i < s.length(); ++i) {
            char c = s.charAt(i);
            switch (c)
                {
                case '\r':
                case '\n':
                case '\\':
                case '\"':
                    sb.append('\\');
                }
            sb.append(c);
        }
        sb.append('\"');
        return sb.toString();
    }

    protected final ArrayList readReply() throws IOException {
        ArrayList reply = new ArrayList();
        char c;
        do {
            String line = input.readLine();
            if (debugOutput != null)
                debugOutput.println("<< "+line);
            if (line.length() < 4)
                throw new TorControlSyntaxError("Line (\""+line+"\") too short");
            String status = line.substring(0,3);
            c = line.charAt(3);
            String msg = line.substring(4);
            String rest = null;
            if (c == '+') {
                StringBuffer data = new StringBuffer();
                while (true) {
                    line = input.readLine();
                    if (debugOutput != null)
                        debugOutput.print("<< "+line);
                    if (line.equals("."))
                        break;
                    else if (line.startsWith("."))
                        line = line.substring(1);
                    data.append(line).append('\n');
                }
                rest = data.toString();
            }
            reply.add(new ReplyLine(status, msg, rest));
        } while (c != ' ');

        return reply;
    }

    /** helper: implement the main background loop. */
    protected void react() throws IOException {
        while (true) {
            ArrayList lst = readReply();
            if (((ReplyLine)lst.get(0)).status.startsWith("6"))
                handleEvent(lst);
            else {
                Waiter w;
                synchronized (waiters) {
                    w = (Waiter) waiters.removeFirst();
                }
                w.setResponse(lst);
            }
        }
    }

    protected synchronized ArrayList sendAndWaitForResponse(String s,String rest)
        throws IOException {
        checkThread();
        Waiter w = new Waiter();
        if (debugOutput != null)
            debugOutput.print(">> "+s);
        synchronized (waiters) {
            output.write(s);
            output.flush();
            if (rest != null)
                writeEscaped(rest);
            waiters.addLast(w);
        }
        ArrayList lst = (ArrayList) w.getResponse();
        for (Iterator i = lst.iterator(); i.hasNext(); ) {
            ReplyLine c = (ReplyLine) i.next();
            if (! c.status.startsWith("2"))
                throw new TorControlError("Error reply: "+c.msg);
        }
        return lst;
    }

    /** Helper: decode a CMD_EVENT command and dispatch it to our
     * EventHandler (if any). */
    protected void handleEvent(ArrayList events) {
        if (handler == null)
            return;

        for (Iterator i = events.iterator(); i.hasNext(); ) {
            ReplyLine line = (ReplyLine) i.next();
            int idx = line.msg.indexOf(' ');
            String tp = line.msg.substring(0, idx).toUpperCase();
            String rest = line.msg.substring(idx+1);
            if (tp.equals("CIRC")) {
                List lst = Bytes.splitStr(null, rest);
                handler.circuitStatus((String)lst.get(1),
                                      (String)lst.get(0),
                                      (String)lst.get(2));
            } else if (tp.equals("STREAM")) {
                List lst = Bytes.splitStr(null, rest);
                handler.streamStatus((String)lst.get(1),
                                     (String)lst.get(0),
                                     (String)lst.get(3));
                // XXXX circID.
            } else if (tp.equals("ORCONN")) {
                List lst = Bytes.splitStr(null, rest);
                handler.orConnStatus((String)lst.get(1), (String)lst.get(0));
            } else if (tp.equals("BW")) {
                List lst = Bytes.splitStr(null, rest);
                handler.bandwidthUsed(Integer.parseInt((String)lst.get(0)),
                                      Integer.parseInt((String)lst.get(1)));
            } else if (tp.equals("NEWDESC")) {
                List lst = Bytes.splitStr(null, rest);
                handler.newDescriptors(lst);
            } else if (tp.equals("DEBUG") ||
                       tp.equals("INFO") ||
                       tp.equals("NOTICE") ||
                       tp.equals("WARN") ||
                       tp.equals("ERR")) {
                handler.message(tp, rest);
            } else {
                handler.unrecognized(tp, rest);
            }
        }
    }

    /** Change the values of the configuration options stored in
     * 'kvList'.  (The format is "key value"). */
    public void setConf(Collection kvList) throws IOException {
        if (kvList.size() == 0)
            return;
        StringBuffer b = new StringBuffer("SETCONF");
        for (Iterator it = kvList.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            int i = kv.indexOf(' ');
            if (i == -1)
                b.append(" ").append(kv);
            b.append(" ").append(kv.substring(0,i)).append("=")
                .append(quote(kv.substring(i+1)));
        }
        b.append("\r\n");
        sendAndWaitForResponse(b.toString(), null);
    }

    public void setDebugging(java.io.PrintWriter w) {
        if (w instanceof java.io.PrintWriter)
            debugOutput = (java.io.PrintWriter) w;
        else
            debugOutput = new java.io.PrintWriter(w, true);
    }
    public void setDebugging(java.io.PrintStream s) {
        debugOutput = new java.io.PrintWriter(s, true);
    }

    public List getConf(Collection keys) throws IOException {
        StringBuffer sb = new StringBuffer("GETCONF");
        for (Iterator it = keys.iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            sb.append(" ").append(key);
        }
        sb.append("\r\n");
        ArrayList lst = sendAndWaitForResponse(sb.toString(), null);
        ArrayList result = new ArrayList();
        for (Iterator it = lst.iterator(); it.hasNext(); ) {
            String kv = ((ReplyLine) it.next()).msg;
            int idx = kv.indexOf('=');
            result.add(new ConfigEntry(kv.substring(0, idx),
                                       kv.substring(idx+1)));
        }
        return result;
    }

    public void setEvents(List events) throws IOException {
        StringBuffer sb = new StringBuffer("SETEVENTS");
        for (Iterator it = events.iterator(); it.hasNext(); ) {
            Object event = it.next();
            if (event instanceof String) {
                sb.append(" ").append((String)event);
            } else {
                int i = ((Number) event).intValue();
                sb.append(" ").append(EVENT_NAMES[i]);
            }
        }
        sb.append("\r\n");
        sendAndWaitForResponse(sb.toString(), null);
    }

    public void authenticate(byte[] auth) throws IOException {
        String cmd = "AUTHENTICATE " + Bytes.hex(auth) + "\r\n";
        sendAndWaitForResponse(cmd, null);
    }

    public void saveConf() throws IOException {
        sendAndWaitForResponse("SAVECONF\r\n", null);
    }

    public void signal(String signal) throws IOException {
        String cmd = "AUTHENTICATE " + signal + "\r\n";
        sendAndWaitForResponse(cmd, null);
    }

    public Map mapAddresses(Collection kvLines) throws IOException {
        StringBuffer sb = new StringBuffer("MAPADDRESS");
        for (Iterator it = kvLines.iterator(); it.hasNext(); ) {
            String kv = (String) it.next();
            int i = kv.indexOf(' ');
            sb.append(" ").append(kv.substring(0,i)).append("=")
                .append(quote(kv.substring(i+1)));
        }
        sb.append("\r\n");
        ArrayList lst = sendAndWaitForResponse(sb.toString(), null);
        Map result = new HashMap();
        for (Iterator it = lst.iterator(); it.hasNext(); ) {
            String kv = ((ReplyLine) it.next()).msg;
            int idx = kv.indexOf('=');
            result.put(kv.substring(0, idx),
                       kv.substring(idx+1));
        }
        return result;
    }

    public Map getInfo(Collection keys) throws IOException {
        StringBuffer sb = new StringBuffer("GETINFO");
        for (Iterator it = keys.iterator(); it.hasNext(); ) {
            sb.append(" ").append((String)it.next());
        }
        sb.append("\r\n");
        ArrayList lst = sendAndWaitForResponse(sb.toString(), null);
        Map m = new HashMap();
        for (Iterator it = lst.iterator(); it.hasNext(); ) {
            ReplyLine line = (ReplyLine) it.next();
            int idx = line.msg.indexOf('=');
            if (idx<0)
                break;
            String k = line.msg.substring(0,idx);
            Object v;
            if (line.rest != null) {
                v = line.rest;
            } else {
                v = line.msg.substring(idx+1);
            }
            m.put(k, v);
        }
        return m;
    }

    public String extendCircuit(String circID, String path) throws IOException {
        ArrayList lst = sendAndWaitForResponse(
                          "EXTENDCIRCUIT "+circID+" "+path+"\r\n", null);
        return ((ReplyLine)lst.get(0)).msg;
    }

    public void attachStream(String streamID, String circID)
        throws IOException {
        sendAndWaitForResponse("ATTACHSTREAM "+streamID+" "+circID+"\r\n", null);
    }

    /** Tell Tor about the server descriptor in 'desc' */
    public String postDescriptor(String desc) throws IOException {
        ArrayList lst = sendAndWaitForResponse("+POSTDESCRIPTOR\r\n", desc);
        return ((ReplyLine)lst.get(0)).msg;
    }

    /** Tell Tor to change the target of the stream identified by 'streamID'
     * to 'address'.
     */
    public void redirectStream(String streamID, String address) throws IOException {
        sendAndWaitForResponse("REDIRECTSTREAM "+streamID+" "+address+"\r\n",
                               null);
    }

    /** Tell Tor to close the stream identified by 'streamID'.
     */
    public void closeStream(String streamID, byte reason)
        throws IOException {
        sendAndWaitForResponse("CLOSESTREAM "+streamID+" "+reason+"\r\n",null);
    }

    /** Tell Tor to close the circuit identified by 'streamID'.
     */
    public void closeCircuit(String circID, boolean ifUnused) throws IOException {
        sendAndWaitForResponse("CLOSECIRCUIT "+circID+
                               (ifUnused?" IFUNUSED":"")+"\r\n", null);
    }

}

