// $Id$
// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package net.freehaven.tor.control;

/**
 * Abstract interface whose methods are invoked when Tor sends us an event.
 *
 * @see TorControlConnection#setEventHandler
 * @see TorControlConnection#setEvents
 */
public interface EventHandler {
    /**
     * Invoked when a circuit's status has changed.
     * See TorControlCommands.CIRC_STATUS_* for possible status codes.
     */
    public void circuitStatus(String status, String circID, String path);
    /**
     * Invoked when a stream's status has changed.
     * See TorControlCommands.STREAM_STATUS_* for possible status codes.
     */
    public void streamStatus(String status, String streamID, String target);
    /**
     * Invoked when the status of a connection to an OR has changed.
     * See TorControlCommands.OR_CONN_STATUS_* for possible status codes.
     */
    public void orConnStatus(String status, String orName);
    /**
     * Invoked once per second with the number of bytes read an written in
     * the last secone.
     */
    public void bandwidthUsed(long read, long written);
    /**
     * Invoked whenever Tor learns about new ORs.
     */
    public void newDescriptors(java.util.List orList);
    /**
     * Invoked when Tor logs a message.
     */
    public void message(String severity, String msg);
    /**
     * Invoked in an unspecified handler.
     */
    public void unrecognized(String type, String msg);

}

