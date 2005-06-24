package net.freehaven.tor.control;

/**
 * An exception raised when Tor behaves in an unexpected way.
 */
public class TorControlSyntaxError extends RuntimeException {
    public TorControlSyntaxError(String s) { super(s); }
}

