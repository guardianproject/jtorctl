// $Id$
// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package net.freehaven.tor.control;

/**
 * An exception raised when Tor tells us about an error.
 */
public class TorControlError extends RuntimeException {
    int errorType;
    public TorControlError(int type, String s) {
        super(s);
        errorType = type;
    }
    public int getErrorType() {
        return errorType;
    }
    public String getErrorMsg() {
        try {
            return TorControlCommands.ERROR_MSGS[errorType];
        } catch (ArrayIndexOutOfBoundsException ex) {
            return "Unrecongized error #"+errorType;
        }
    }
}