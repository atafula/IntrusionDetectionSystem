package java.ids;

import java.util.Map;

public class AlertManager {
        public static void raiseAlert(Map<String, String> features) {
        System.out.println("INTRUSION DETECTED:");
        features.forEach((k, v) -> System.out.println(k + ": " + v));
    }

    public static void saveAlertToFile(Map<String, String> features) {
        // Guarda alerta en un archivo (opcional)
    }
}
