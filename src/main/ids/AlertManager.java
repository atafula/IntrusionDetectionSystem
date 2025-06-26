package ids;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AlertManager {

    private static final Logger logger = Logger.getLogger(AlertManager.class.getName());
    private static final String alert_file = "alerts.log";
    private static final DateTimeFormatter time_format = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    //Prints an alert message
    public static void raiseAlert(Map<String, String> features) {
        System.out.println("----- INTRUSION DETECTED -----");
        features.forEach((k, v) -> System.out.println(k + ": " + v));
        System.out.println("------------------------------");
        saveAlertToFile(features);
    }

    // Saves the alert details
    public static void saveAlertToFile(Map<String, String> features) {
        String timestamp = LocalDateTime.now().format(time_format);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(alert_file, true))) {
            writer.write("----- INTRUSION DETECTED at " + timestamp + " -----\n");
            for (Map.Entry<String, String> entry : features.entrySet()) {
                writer.write(entry.getKey() + ": " + entry.getValue() + "\n");
            }
            writer.write("----------------------------------------------\n");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error writing alert to file: " + e.getMessage(), e);
        }
    }
}