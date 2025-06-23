package java.ids;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class PacketSniffer {
    
    // 
    public void startCapture() {
        try {
            ProcessBuilder builder = new ProcessBuilder("tshark", "-l", "-T", "json");
            Process process = builder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                handlePacket(line);
            }
        } catch (IOException e) {
            System.err.println("Error starting tshark: " + e.getMessage());
        }
    }

    private void handlePacket(String rawData) {
        Map<String, String> features = FeatureExtractor.extract(rawData);
        boolean isAttack = Predictor.predict(features);
        if (isAttack) {
            AlertManager.raiseAlert(features);
        }
    }

}
