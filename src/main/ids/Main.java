package ids;

import java.io.IOException;
import java.util.logging.*;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());

    // Start the Sniffer
    public static void main(String[] args) {
        setupLogger();
        System.out.println("--- STARTING PACKETSNIFFER ---");
        logger.info("--- STARTING PACKETSNIFFER ---");

        PacketSniffer sniffer = new PacketSniffer();
        sniffer.startCapture();
        sniffer.stopCapture();
        logger.info("PacketSniffer stopped");
        System.out.println("PacketSniffer stopped");
    }

    // Logs setup
    private static void setupLogger() {
        try {
            Logger root = Logger.getLogger("");

            // Remove all existing handlers
            for (Handler handler : root.getHandlers()) {
                root.removeHandler(handler);
            }

            // Configure FileHandler to write logs to a file
            FileHandler fileHandler = new FileHandler("app.log", true);
            fileHandler.setFormatter(new Formatter() {
                @Override
                public String format(LogRecord record) {
                    return String.format("%s: %s%n", record.getLevel(), formatMessage(record));
                }
            });

            root.addHandler(fileHandler);
            root.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Logger setup failed: " + e.getMessage());
        }
    }

}
