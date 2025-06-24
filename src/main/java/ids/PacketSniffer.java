package java.ids;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class PacketSniffer {
    
    // Starts packet capturing by launching tshark process
    public void startCapture() {
        try {
            // Build the process to run tshark with JSON output and line buffering
            ProcessBuilder builder = new ProcessBuilder("tshark", "-l", "-T", "json");
            Process process = builder.start();

            // Read output from tshark line by line
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Handle each captured packet
                handlePacket(line);
            }
        } catch (IOException e) {
            // Error handling when starting tshark process
            System.err.println("Error starting tshark: " + e.getMessage());
        }
    }

    // Process raw packet JSON string, extract features, predict if attack, and raise alert if true
    private void handlePacket(String rawData) {
        Map<String, String> features = FeatureExtractor.extract(rawData);
        boolean isAttack = Predictor.predict(features);
        if (isAttack) {
            AlertManager.raiseAlert(features);
        }
    }

}
