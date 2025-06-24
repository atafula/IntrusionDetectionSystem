package java.ids;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public class AlertManager {

    // Prints an alert message to the console with all feature key-value pairs
    public static void raiseAlert(Map<String, String> features) {
        System.out.println("----- INTRUSION DETECTED -----");  // ----- INTRUSION DETECTED -----
        features.forEach((k, v) -> System.out.println(k + ": " + v));  // Print each feature key and value
        System.out.println("------------------------------");  // ------------------------------
    }

    // Saves the alert details with a timestamp to a file named "alerts.log"
    public static void saveAlertToFile(Map<String, String> features) {
        String filename = "alerts.log";
        // Get current date-time formatted as "yyyy-MM-dd HH:mm:ss"
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
            // Write header with timestamp
            writer.write("----- INTRUSION DETECTED at " + timestamp + " -----\n");
            // Write each feature key-value pair to the file
            for (Map.Entry<String, String> entry : features.entrySet()) {
                writer.write(entry.getKey() + ": " + entry.getValue() + "\n");
            }
            // Write footer
            writer.write("----------------------------------------------\n");
        } catch (IOException e) {
            // Print error if file writing fails
            System.err.println("Error writing alert to file: " + e.getMessage());
        }
    }
    
}
