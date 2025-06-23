package java.ids;

import java.util.HashMap;
import java.util.Map;

public class FeatureExtractor {
       public static Map<String, String> extract(String rawPacket) {
        // Parsear raw data (JSON o texto plano)
        // Extraer: protocolo, tamaño, flags, puertos, etc.
        // Devolver como mapa clave/valor
        return new HashMap<>();
    } 
    private static String parseProtocol(String raw) {
        // Extrae protocolo, por ejemplo TCP/UDP/ICMP
        return "";
    }

    private static int getPacketSize(String raw) {
    
        return 0;
    }
}
