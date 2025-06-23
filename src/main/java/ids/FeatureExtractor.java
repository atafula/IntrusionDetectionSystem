package java.ids;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class FeatureExtractor {
    public static Map<String, String> extract(String rawPacket) {
        Map<String, String> features = new HashMap<>();

        try {
            JSONArray packets = new JSONArray(rawPacket);
            JSONObject packet = packets.getJSONObject(0); // tomamos el primer paquete

            JSONObject layers = packet.getJSONObject("_source").getJSONObject("layers");

            String protocol = parseProtocol(layers);
            features.put("protocol", protocol);

            String srcPort = getValueOrDefault(layers, "tcp.srcport", "0");
            String dstPort = getValueOrDefault(layers, "tcp.dstport", "0");

            features.put("src_port", srcPort);
            features.put("dst_port", dstPort);

            String length = getValueOrDefault(layers, "frame.len", "0");
            features.put("length", length);

            features.put("flag_syn", layers.has("tcp.flags.syn") ? "1" : "0");

        } catch (Exception e) {
            System.err.println("Failed to extract features: " + e.getMessage());
        }

        return features;
    }

    private static String parseProtocol(JSONObject layers) {
        if (layers.has("ip")) return "IP";
        if (layers.has("tcp")) return "TCP";
        if (layers.has("udp")) return "UDP";
        if (layers.has("icmp")) return "ICMP";
        return "UNKNOWN";
    }

    private static String getValueOrDefault(JSONObject obj, String key, String defaultValue) {
        return obj.has(key) ? obj.getJSONArray(key).getString(0) : defaultValue;
    }
}
