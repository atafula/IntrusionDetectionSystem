package ids;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

public class Predictor {

    private static final Logger logger = Logger.getLogger(Predictor.class.getName());

    // Sends feature data to a Python script for prediction
    public static boolean predict(Map<String, String> features) {
        
        try {
            logger.info("Starting Prediction process...");
            System.out.println("Starting Prediction process...");

            Process process = new ProcessBuilder("python", "scripts/predict.py").start();

            // Send JSON input
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))) {
                String jsonString = new JSONObject(features).toString();
                writer.write(jsonString);
                writer.flush();
                logger.info("Sent JSON to Python script: " + jsonString);
                System.out.println("Sent JSON to Python script: " + jsonString);
            }

            // Read output
            String result;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                result = reader.readLine();
                logger.info("Received prediction: " + result);
                System.out.println("Received prediction: " + result);
            }

            // Wait for process and return result
            if (process.waitFor() != 0) {
                logger.warning("Python script exited");
                return false;
            }

            boolean isAttack = false;
            if (result != null) {
                isAttack = "attack".equalsIgnoreCase(result.trim());
            }
            
            return isAttack;

        } catch (IOException | InterruptedException e) {
            logger.log(Level.SEVERE, "Prediction error", e);
            return false;
        }
        
    }
}
