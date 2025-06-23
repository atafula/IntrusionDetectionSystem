package java.ids;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Map;

import org.json.JSONObject;

public class Predictor {
    
    public static boolean predict(Map<String, String> features) {
        try {
            ProcessBuilder pb = new ProcessBuilder("python", "scripts/predict.py");
            Process process = pb.start();

            JSONObject json = new JSONObject(features);

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
            writer.write(json.toString());
            writer.flush();
            writer.close();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = reader.readLine();
            reader.close();

            return result != null && result.trim().equalsIgnoreCase("attack");

        } catch (IOException e) {
            System.err.println("Prediction error: " + e.getMessage());
            return false;
        }
    }

}
