// $Id$
// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package net.freehaven.tor.control.examples;

import net.freehaven.tor.control.*;
import java.io.PrintWriter;
import java.util.Iterator;

public class DebuggingEventHandler implements EventHandler, TorControlCommands {

    protected PrintWriter out;

    public DebuggingEventHandler(PrintWriter p) {
        out = p;
    }

    public void circuitStatus(int status, int circID, String path) {
        out.println("Circuit "+Integer.toHexString(circID)+" is now "+
                    CIRC_STATUS_NAMES[status]+" (path="+path+")");
    }
    public void streamStatus(int status, int streamID, String target) {
        out.println("Stream "+Integer.toHexString(streamID)+" is now "+
                    STREAM_STATUS_NAMES[status]+" (target="+target+")");
    }
    public void orConnStatus(int status, String orName) {
        out.println("OR connection to "+orName+" is now "+
                    OR_CONN_STATUS_NAMES[status]);
    }
    public void bandwidthUsed(long read, long written) {
        out.println("Bandwidth usage: "+read+" bytes read; "+
                    written+" bytes written.");
    }
    public void newDescriptors(java.util.List orList) {
        out.println("New descriptors for routers:");
        for (Iterator i = orList.iterator(); i.hasNext(); )
            out.println("   "+i.next());
    }
    public void message(int type, String msg) {
        String tp;
        switch (type) {
            case EVENT_MSG_INFO: tp = "info"; break;
            case EVENT_MSG_NOTICE: tp = "notice"; break;
            case EVENT_MSG_WARN: tp = "warn"; break;
            case EVENT_MSG_ERROR: tp = "error"; break;
            default:
                throw new Error("EventHandler.message() called with bad type: "+
                                type);
        }
        out.println("["+tp+"] "+msg.trim());
    }

}