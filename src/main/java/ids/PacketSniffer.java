package java.ids;

import java.util.Map;

public class PacketSniffer {
    
    public void startCapture() {
        // Ejecuta tshark como proceso externo
        // Recolecta salida línea por línea
        // Por cada paquete: parsearlo y pasarlo a FeatureExtractor
    }

    private void handlePacket(String rawData) {
        Map<String, String> features = FeatureExtractor.extract(rawData);
        boolean isAttack = Predictor.predict(features);
        if (isAttack) {
            AlertManager.raiseAlert(features);
        }
    }

    private String executeTsharkCommand() {
        // Ejecutar el comando de captura
        return "";
    }
}
