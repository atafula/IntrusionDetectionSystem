package ids;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.logging.*;

public class PacketSniffer {
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private Process process;

    // Starts packet capturing by launching tshark process
    public void startCapture() {
        try {
            // Build the process to run tshark
            logger.info("Starting Tshark...");
            System.out.println("Starting Tshark...");

            // Using NIC (tshark -D)
            ProcessBuilder builder = new ProcessBuilder(
                "tshark",
                "-i", "\\Device\\NPF_{83F29D86-17C5-4644-8D2E-633ABB07AD82}",
                "-l",
                "-T", "ek"
            );

            process = builder.start();
            logger.info("Tshark started");
            System.out.println("Tshark started");

            // Read from tshark line by line
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            logger.info("------------------------------");
            System.out.println("------------------------------");
            while ((line = reader.readLine()) != null) {
                // Handle each packet
                if (!line.trim().isEmpty()) {
                    if(line.contains("\"layers\"")) {
                        logger.info("Captured packet JSON: " + line);
                        handlePacket(line);
                        logger.info("------------------------------");
                        System.out.println("------------------------------");
                    }
                } else {
                    logger.log(Level.FINE, "Failed to extract features, not a valid packet: " + line); 
                }       
            }
        } catch (IOException e) {
            // Error handling when starting tshark
            System.err.println("Error starting tshark: " + e.getMessage());
        }
    }

    // Stops packet capturing
    public void stopCapture() {
        if (process != null) {
            process.destroy();
        }
    }

    // Extract features and predict if attack
    public void handlePacket(String rawData) {
        Map<String, String> features = FeatureExtractor.extract(rawData);
        boolean isAttack = Predictor.predict(features);
        if (isAttack) {
            AlertManager.raiseAlert(features);
        }
    }

}
