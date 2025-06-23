package java.ids;

import java.util.Map;

public class Predictor {
        public static boolean predict(Map<String, String> features) {
        // Opción 1: llamar a script Python con args o JSON
        // Opción 2: hacer HTTP POST a localhost:5000 (Flask API)
        // Recibir predicción (normal vs. ataque)
        return false;
    }

    private static String buildJson(Map<String, String> features) {
        // Convierte mapa a JSON
        return "";
    }

    private static String sendRequest(String json) {
        // Llama a Python API
        return "";
    }
}
