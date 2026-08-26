import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.util.FilteredObjectInputStream;

import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Faithful stand-in for the official log4j-samples ObjectInputStreamLogEventBridge:
 * an unauthenticated TCP log receiver that reads one serialized LogEvent per
 * connection through Log4j's own FilteredObjectInputStream (FOIS) allowlist.
 *
 * The receiver does NOT trust the network: FOIS is exactly the defense-in-depth
 * allowlist Log4j ships. This program adds no gadgets and no attacker classes of
 * its own -- its only classpath is log4j + (for the realistic PoC) commons-collections.
 */
public class Receiver {
    public static void main(String[] args) throws Exception {
        final int port = Integer.parseInt(args[0]);
        final ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress("0.0.0.0", port));
        System.out.println("[receiver] FilteredObjectInputStream bridge on 0.0.0.0:" + port
                + "  (no auth, no TLS)  filter=" + System.getProperty("jdk.serialFilter", "<none>"));
        for (;;) {
            try (Socket s = ss.accept()) {
                System.out.println("[receiver] connection from " + s.getRemoteSocketAddress());
                try (ObjectInputStream in = new FilteredObjectInputStream(s.getInputStream())) {
                    final Object o = in.readObject();
                    final LogEvent event = (LogEvent) o;
                    // getMessage() reflects the SimpleMessage fallback: the receiver
                    // sees a benign event and keeps processing -- the exploit is silent.
                    System.out.println("[receiver] processed event OK: level=" + event.getLevel()
                            + " logger=" + event.getLoggerName()
                            + " message=\"" + event.getMessage().getFormattedMessage() + "\"");
                } catch (Throwable t) {
                    System.out.println("[receiver] readObject REJECTED/failed: "
                            + t.getClass().getName() + ": " + t.getMessage());
                }
            } catch (Throwable t) {
                System.out.println("[receiver] connection error: " + t);
            }
        }
    }
}
