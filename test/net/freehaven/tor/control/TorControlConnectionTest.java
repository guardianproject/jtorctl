package net.freehaven.tor.control;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TorControlConnectionTest {

    @Rule
    public TemporaryFolder testDir = new TemporaryFolder();

    private static final int UNSET_PORT = -1;
    private static int controlPort = UNSET_PORT;
    private static int socksPort = UNSET_PORT;

    private InetSocketAddress controlPortSocketAddress;
    private TorControlConnection torControlConnection;

    private CountDownLatch circuitStatusLatch = new CountDownLatch(1);
    private CountDownLatch streamStatusLatch = new CountDownLatch(1);
    private CountDownLatch orConnStatusLatch = new CountDownLatch(1);
    private CountDownLatch bandwidthUsedLatch = new CountDownLatch(1);
    private CountDownLatch newDescriptorsLatch = new CountDownLatch(1);
    private CountDownLatch messageLatch = new CountDownLatch(1);

    private CountDownLatch builtLatch = new CountDownLatch(1);

    @Before
    public void setUp() {
        controlPort = UNSET_PORT;
        torControlConnection = null;
    }

    @Test
    public void test() throws IOException, InterruptedException {
        final CountDownLatch finishedLatch = new CountDownLatch(1);
        final File tor = new File("/usr/bin/tor");
        Assume.assumeTrue(tor.canExecute());

        final File cacheDir = testDir.newFolder("cache");
        assertTrue(cacheDir.isDirectory());
        final File dataDir = testDir.newFolder("data");
        assertTrue(dataDir.isDirectory());
        final File torrc = new File(testDir.getRoot(), "torrc");
        final File controlPortFile = new File(testDir.getRoot(), "ControlPortWriteToFile");

        Thread torThread = new Thread("tor") {
            @Override
            public void run() {
                Process process = null;
                try {
                    String[] cmdline = {
                            tor.getAbsolutePath(),
                            "-f", torrc.getAbsolutePath(),
                            "--ignore-missing-torrc",
                            "--RunAsDaemon", "1",
                            "--CacheDirectory", cacheDir.getAbsolutePath(),
                            "--DataDirectory", dataDir.getAbsolutePath(),
                            "--ControlPortWriteToFile", controlPortFile.getAbsolutePath(),
                            "--CookieAuthentication", "0",
                            "--ControlPort", "auto",
                            "--SocksPort", "auto",
                            "--Log", "debug file " + testDir.getRoot() + "/debug.log",
                    };
                    System.out.println(String.join(" ", cmdline));
                    System.out.println("START");
                    process = Runtime.getRuntime().exec(cmdline);
                    System.out.println("RUNNING");
                    while (true) {
                        System.out.println(String.join("\n", IOUtils.readLines(process.getInputStream())));
                        System.out.println(String.join("\n", IOUtils.readLines(process.getErrorStream())));
                        if (!process.isAlive()) {
                            break;
                        }
                    }
                    System.out.println("exit value: " + process.exitValue());
                } catch (IOException e) {
                    try {
                        System.out.println(String.join("\n", IOUtils.readLines(process.getInputStream())));
                        System.out.println(String.join("\n", IOUtils.readLines(process.getErrorStream())));
                        process.destroyForcibly();
                    } catch (Exception e1) {
                        // ignored
                    }
                    e.printStackTrace();
                }
                finishedLatch.countDown();
            }
        };
        torThread.start();

        controlPortSocketAddress = getControlPortSocketAddress(controlPortFile);
        controlPort = controlPortSocketAddress.getPort();
        assertNotEquals(UNSET_PORT, controlPort);
        assertFalse(isPortAvailable(controlPort));
        assertNull(torControlConnection);

        Socket socket = new Socket(Proxy.NO_PROXY);
        socket.connect(controlPortSocketAddress);
        torControlConnection = new TorControlConnection(socket.getInputStream(), socket.getOutputStream());
        torControlConnection.launchThread(true);
        torControlConnection.authenticate(new byte[0]);
        torControlConnection.setEventHandler(eventHandler);

        try {
            torControlConnection.setEvents(Arrays.asList(
                    "NEWCONSENSUS", TorControlCommands.EVENT_CONN_BW
            ));
            fail();
        } catch (IllegalArgumentException ignored) {}

        torControlConnection.setEvents(Arrays.asList(
                TorControlCommands.EVENT_OR_CONN_STATUS,
                TorControlCommands.EVENT_CIRCUIT_STATUS,
                TorControlCommands.EVENT_BANDWIDTH_USED,
                TorControlCommands.EVENT_NOTICE_MSG,
                TorControlCommands.EVENT_WARN_MSG,
                TorControlCommands.EVENT_ERR_MSG
        ));
        socksPort = getPortFromGetInfo("net/listeners/socks");
        builtLatch.await();
        InetSocketAddress isa = new InetSocketAddress("localhost", socksPort);
        Proxy proxy = new Proxy(Proxy.Type.SOCKS, isa);
        assertTrue(checkIsTor(new URL("https://check.torproject.org/api/ip").openConnection(proxy)));
        waitToReceiveAllEvents();

        final CountDownLatch hsDescLatch = new CountDownLatch(1);
        RawEventListener listener = new RawEventListener() {
            @Override
            public void onEvent(String name, String data) {
                if (TorControlCommands.EVENT_HS_DESC.equals(name)) {
                    hsDescLatch.countDown();
                }
            }
        };
        torControlConnection.setEvents(Arrays.asList(TorControlCommands.EVENT_HS_DESC));
        torControlConnection.addRawEventListener(listener);
        torControlConnection.hsFetch("facebookcorewwwi");
        hsDescLatch.await();

        String[] configLines = {
                "DisableNetwork 1",
                "HTTPTunnelPort 9999",
        };
        torControlConnection.loadConf(configLines);
        ConfigEntry entry = torControlConnection.getConf("DisableNetwork").get(0);
        assertEquals("DisableNetwork", entry.key);
        assertEquals("1", entry.value);
        entry = torControlConnection.getConf("HTTPTunnelPort").get(0);
        assertEquals("HTTPTunnelPort", entry.key);
        assertEquals("9999", entry.value);

        torControlConnection.shutdownTor(TorControlCommands.SIGNAL_SHUTDOWN);

        finishedLatch.await(50, TimeUnit.SECONDS);
        torThread.interrupt();
    }

    private EventHandler eventHandler = new EventHandler() {
        @Override
        public void circuitStatus(String status, String circID, String path) {
            circuitStatusLatch.countDown();
            System.out.println("circuitStatus(" + status + ", " + circID + ", " + path + ")");
            if (TorControlCommands.CIRC_EVENT_BUILT.equals(status)) {
                builtLatch.countDown();
            }
        }

        @Override
        public void streamStatus(String status, String streamID, String target) {
            streamStatusLatch.countDown();
            System.out.println("streamStatus(" + status + ", " + streamID + ", " + target + ")");
        }

        @Override
        public void orConnStatus(String status, String orName) {
            orConnStatusLatch.countDown();
            System.out.println("orConnStatus(" + status + ", " + orName + ")");
        }

        @Override
        public void bandwidthUsed(long read, long written) {
            bandwidthUsedLatch.countDown();
            System.out.println("bandwidthUsed(" + read + ", " + written + ")");
        }

        @Override
        public void newDescriptors(List<String> orList) {
            newDescriptorsLatch.countDown();
            System.out.println("newDescriptors(" + String.join(", ", orList) + ")");
        }

        @Override
        public void message(String severity, String msg) {
            messageLatch.countDown();
            System.out.println("message(" + severity + ", " + msg + ")");
        }

        @Override
        public void unrecognized(String type, String msg) {
            System.out.println("unrecognized(" + type + ", " + msg + ")");
        }
    };

    private InetSocketAddress getControlPortSocketAddress(File file) throws IOException, InterruptedException {
        while (!file.canRead()) {
            System.out.println("waiting for controlPortFile " + file);
            Thread.sleep(1000);
        }
        String[] address = FileUtils.readFileToString(file).trim().split("=")[1].split(":");
        System.out.println("ControlPort: " + address[0] + ":" + address[1]);
        return new InetSocketAddress(address[0], Integer.parseInt(address[1]));
    }

    private int getPortFromGetInfo(String key) throws IOException {
        final String value = torControlConnection.getInfo(key);
        System.out.println("torControlConnection.getInfo(" + key + ") " + value);
        return Integer.parseInt(value.substring(value.lastIndexOf(':') + 1, value.length() - 1));
    }

    private static boolean isPortAvailable(int port) {
        try {
            (new ServerSocket(port)).close();
            return true;
        } catch (IOException e) {
            // Could not connect.
            return false;
        }
    }

    private void waitToReceiveAllEvents() throws InterruptedException {
        HashSet<String> events = new HashSet<>(Arrays.asList(
                ""
        ));
        long total = Long.MAX_VALUE;
        do {
            total = circuitStatusLatch.getCount() +
                    //streamStatusLatch.getCount() +
                    orConnStatusLatch.getCount() +
                    bandwidthUsedLatch.getCount() +
                    messageLatch.getCount();
            System.out.println("\nWAITING for " + total + " events.\n");
            Thread.sleep(1000);
        } while (total > 0);
    }

    private static boolean checkIsTor(URLConnection connection) throws IOException {
        String contents = IOUtils.toString(connection.getInputStream(), connection.getContentEncoding());
        JSONObject jsonObject = new JSONObject(contents);
        return jsonObject.getBoolean("IsTor");
    }
}