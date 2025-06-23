package java.ids;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public class AlertManager {

    public static void raiseAlert(Map<String, String> features) {
        System.out.println("----- INTRUSION DETECTED -----");
        features.forEach((k, v) -> System.out.println(k + ": " + v));
        System.out.println("------------------------------");
    }

    public static void saveAlertToFile(Map<String, String> features) {
        String filename = "alerts.log";
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
            writer.write("----- INTRUSION DETECTED at " + timestamp + " -----\n");
            for (Map.Entry<String, String> entry : features.entrySet()) {
                writer.write(entry.getKey() + ": " + entry.getValue() + "\n");
            }
            writer.write("----------------------------------------------\n");
        } catch (IOException e) {
            System.err.println("Error writing alert to file: " + e.getMessage());
        }
    }
}
