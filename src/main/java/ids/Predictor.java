package java.ids;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Map;

import org.json.JSONObject;

public class Predictor {
    
    /**
     * Sends feature data to a Python script for prediction
     * and returns whether the input is classified as an attack.
     * 
     * @param features Map of feature names and their string values
     * @return true if prediction is "attack", false otherwise
     */
    public static boolean predict(Map<String, String> features) {
        try {
            // Prepare to execute the Python prediction script
            ProcessBuilder pb = new ProcessBuilder("python", "scripts/predict.py");
            Process process = pb.start();

            // Convert features map to JSON string
            JSONObject json = new JSONObject(features);

            // Send JSON input to the Python script's stdin
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
            writer.write(json.toString());
            writer.flush();
            writer.close();

            // Read prediction result from Python script's stdout
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = reader.readLine();
            reader.close();

            // Return true if result equals "attack" (case-insensitive), false otherwise
            return result != null && result.trim().equalsIgnoreCase("attack");

        } catch (IOException e) {
            // Log any IO errors during prediction process
            System.err.println("Prediction error: " + e.getMessage());
            return false;
        }
    }

}
