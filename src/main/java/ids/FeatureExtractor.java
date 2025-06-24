package java.ids;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class FeatureExtractor {

    // Extracts network features from a raw JSON packet string and returns them as a Map
    public static Map<String, String> extract(String rawPacket) {
        Map<String, String> features = new HashMap<>();

        try {
            // Parse the raw packet string as a JSON array
            JSONArray packets = new JSONArray(rawPacket);
            // Get the first packet object
            JSONObject packet = packets.getJSONObject(0);

            // Navigate to the layers JSON object inside the packet
            JSONObject layers = packet.getJSONObject("_source").getJSONObject("layers");

            // Determine protocol type and add it to features
            String protocol = parseProtocol(layers);
            features.put("protocol", protocol);

            // Extract source and destination TCP ports, default to "0" if missing
            String srcPort = getValueOrDefault(layers, "tcp.srcport", "0");
            String dstPort = getValueOrDefault(layers, "tcp.dstport", "0");

            features.put("src_port", srcPort);
            features.put("dst_port", dstPort);

            // Extract frame length, default to "0" if missing
            String length = getValueOrDefault(layers, "frame.len", "0");
            features.put("length", length);

            // Check if SYN flag is present, add "1" if yes, "0" otherwise
            features.put("flag_syn", layers.has("tcp.flags.syn") ? "1" : "0");

        } catch (Exception e) {
            // Print error message if feature extraction fails
            System.err.println("Failed to extract features: " + e.getMessage());
        }

        return features;
    }

    // Parses protocol name from layers JSONObject, returns "UNKNOWN" if none matched
    private static String parseProtocol(JSONObject layers) {
        if (layers.has("ip")) return "IP";
        if (layers.has("tcp")) return "TCP";
        if (layers.has("udp")) return "UDP";
        if (layers.has("icmp")) return "ICMP";
        return "UNKNOWN";
    }

    // Helper method to get the first string value from a JSONArray by key or return default
    private static String getValueOrDefault(JSONObject obj, String key, String defaultValue) {
        return obj.has(key) ? obj.getJSONArray(key).getString(0) : defaultValue;
    }
}
