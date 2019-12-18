
# jtorctl

A Java library for controlling a Tor instance via its [control
port](https://spec.torproject.org/control-spec).  It is used in
Android apps like Tor Browser, Orbot, Briar, and others.

It is available on Maven Central, and can be used as maven/gradle
library, e.g.:

```
    implementation info.guardianproject:jtorctl:0.4.2.5'
```

## Updating

This library is meant to be paired with a given version of Tor, since
Tor adds and removes commands, events, etc in some new releases.
`./tools/generate-TorControlCommands.py` is a helper script for making
updated versions of the library.  It overwrites these files with updates:

* _src/net/freehaven/tor/control/TorControlCommands.java_
* _src/net/freehaven/tor/control/RawEventListener.java_
* _src/net/freehaven/tor/control/EventListener.java_

It also generates
_src/net/freehaven/tor/control/TorControlConnection.java.gen_, which
can then be manually synced with
_src/net/freehaven/tor/control/TorControlConnection.java_ using a tool
like `meld`.
