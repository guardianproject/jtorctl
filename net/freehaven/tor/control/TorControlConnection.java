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
public abstract class TorControlConnection// implements TorControlCommands {
{
    public static class ConfigEntry {
        public ConfigEntry(String k, String v) { key = k; value = v; }
        public final String key;
        public final String value;
    }

    protected EventHandler handler;

    protected LinkedList waiters;

    protected Thread thread;

    static class Waiter {
        Object response;
        public synchronized Object getResponse() {
            try {
                while (response == null) {
                    wait();
                }
            } catch (InterruptedException ex) {
                return null;
            }
            return response;
        }
        public synchronized void setResponse(Object response) {
            this.response = response;
            notifyAll();
        }
    }

    protected static int detectVersion(java.io.InputStream input,
                                       java.io.OutputStream output)
        throws IOException
    {
        java.io.DataInputStream dInput = new java.io.DataInputStream(input);
        byte out[] = { 0, 0, 13, 10 };
        output.write(out);

        int len = dInput.readUnsignedShort();
        int tp = dInput.readUnsignedShort();
        if (tp == 0) {
            byte err[] = new byte[len];
            dInput.readFully(err);
            return 0;
        } else if ((len & 0xff00) != 0x0a00 &&
                   (len & 0x00ff) != 0x000a &&
                   (tp  & 0xff00) != 0x0a00 &&
                   (tp  & 0x00ff) != 0x000a) {
            while (input.read() != '\n')
                ;
        }
        return 1;
    }

    public static TorControlConnection getConnection(java.net.Socket sock)
        throws IOException
    {
        int version = detectVersion(sock.getInputStream(),
                                    sock.getOutputStream());
        if (version == 0)
            return new TorControlConnection0(sock);
        else
            return new TorControlConnection1(sock);
    }

    protected TorControlConnection() {
        this.waiters = new LinkedList();
    }

    /** Set the EventHandler object that will be notified of any
     * events Tor delivers to this connection.  To make Tor send us
     * events, call setEvents(). */
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
        this.thread = th;
        return th;
    }

    protected final void checkThread() {
        if (thread == null)
            launchThread(true);
    }

    protected abstract void react() throws IOException;

    /** Change the value of the configuration option 'key' to 'val'.
     */
    public void setConf(String key, String value) throws IOException {
        List lst = new ArrayList();
        lst.add(key+" "+value);
        setConf(lst);
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

    /** Change the values of the configuration options stored in
     * 'kvList'.  (The format is "key value"). */
    public abstract void setConf(Collection kvList) throws IOException;

    /** Return the value of the configuration option 'key' */
    public List getConf(String key) throws IOException {
        List lst = new ArrayList();
        lst.add(key);
        return getConf(lst);
    }

    /** Return a key-value map for the configuration options in 'keys' */
    public abstract List getConf(Collection keys) throws IOException;

    /** Tell Tor to begin sending us events of the types listed in 'events'.
     * Elements must be one of the EVENT_* values from TorControlCommands */
    public abstract void setEvents(List events) throws IOException;

    /** Send Tor an authentication sequence 'auth' */
    // XXXX more info about how to set this up securely.
    public abstract void authenticate(byte[] auth) throws IOException;

    /** Tell Tor to save the value of its configuration to disk. */
    public abstract void saveConf() throws IOException;

    /** Send a signal to the Tor process. */
    public abstract void signal(String signal) throws IOException;

    /** Tell Tor to replace incoming addresses with those as listed in 'kvLines'.
     */
    public abstract Map mapAddresses(Collection kvLines) throws IOException;

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
    public abstract Map getInfo(Collection keys) throws IOException;

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
    public abstract String extendCircuit(String circID, String path) throws IOException;

    /**
     * Tell Tor to attach the stream identified by 'streamID' to the circuit
     * identified by 'circID'.
     */
    public abstract void attachStream(String streamID, String circID) throws IOException;

    /** Tell Tor about the server descriptor in 'desc' */
    public abstract String postDescriptor(String desc) throws IOException;

    /** Tell Tor to change the target of the stream identified by 'streamID'
     * to 'address'.
     */
    public abstract void redirectStream(String streamID, String address) throws IOException;

    /** Tell Tor to close the stream identified by 'streamID'.
     */
    public abstract void closeStream(String streamID, byte reason)
        throws IOException;

    /** Tell Tor to close the circuit identified by 'streamID'.
     */
    public abstract void closeCircuit(String circID, boolean ifUnused) throws IOException;

}

