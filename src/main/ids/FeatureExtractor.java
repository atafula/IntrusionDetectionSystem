package ids;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FeatureExtractor {

    private static final Logger logger = Logger.getLogger(FeatureExtractor.class.getName());

    // Extracts relevant network features
    public static Map<String, String> extract(String rawPacket) {
        Map<String, String> features = new HashMap<>();
        
        try {
            JSONArray packets = new JSONArray(rawPacket);
            if (packets.length() == 0) {
                logger.warning("Empty packet array");
                return features;
            }

            JSONObject layers = packets.getJSONObject(0).getJSONObject("_source").getJSONObject("layers");
            features.put("protocol", parseProtocol(layers));
            features.put("src_port", getValueOrDefault(layers, "tcp.srcport", "0"));
            features.put("dst_port", getValueOrDefault(layers, "tcp.dstport", "0"));
            features.put("length", getValueOrDefault(layers, "frame.len", "0"));

            String flagSyn = "0";
            if (layers.has("tcp.flags.syn")) {
                flagSyn = "1";
            }
            features.put("flag_syn", flagSyn);

        } catch (Exception e) {
            logger.log(Level.WARNING, "Failed to extract features", e);
        }

        return features;
    }

    // Determines the protocol used in the packet
    private static String parseProtocol(JSONObject layers) {
        if (layers.has("ip")) return "IP";
        if (layers.has("tcp")) return "TCP";
        if (layers.has("udp")) return "UDP";
        if (layers.has("icmp")) return "ICMP";
        
        return "UNKNOWN";
    }

    // Retrieves a value under a given key
    private static String getValueOrDefault(JSONObject obj, String key, String defaultValue) {
        try {
            if (obj.has(key)) {
                JSONArray arr = obj.getJSONArray(key);
                if (arr.length() > 0) {
                    return arr.getString(0);
                }
            }
        } catch (Exception e) {
            logger.log(Level.FINE, "Error getting key " + key, e);
        }

        return defaultValue;
    }
}
