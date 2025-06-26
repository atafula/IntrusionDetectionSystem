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

        JSONObject packet = new JSONObject(rawPacket);
        JSONObject layers = packet.getJSONObject("layers");
        JSONObject tcp = layers.has("tcp") ? layers.getJSONObject("tcp") : null;
        JSONObject frame = layers.has("frame") ? layers.getJSONObject("frame") : null;

        // Basic packet features
        features.put("Destination Port", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_dstport", "0") : "0");
        features.put("Flow Duration", frame != null ? getValueOrDefault(frame, "frame_frame_time_delta", "0") : "0");
        
        // Packet count features
        features.put("Total Fwd Packets", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_stream_pnum", "0") : "0");
        features.put("Total Backward Packets", "0");
        
        // Packet length features
        features.put("Total Length of Fwd Packets", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_len", "0") : "0");
        features.put("Total Length of Bwd Packets", "0");
        features.put("Fwd Packet Length Max", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_len", "0") : "0");
        features.put("Fwd Packet Length Min", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_len", "0") : "0");
        features.put("Fwd Packet Length Mean", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_len", "0") : "0");
        features.put("Fwd Packet Length Std", "0");
        features.put("Bwd Packet Length Max", "0");
        features.put("Bwd Packet Length Min", "0");
        features.put("Bwd Packet Length Mean", "0");
        features.put("Bwd Packet Length Std", "0");
        
        // Flow rate features
        features.put("Flow Bytes/s", frame != null ? getValueOrDefault(frame, "frame_frame_len", "0") : "0");
        features.put("Flow Packets/s", "0");
        
        // IAT (Inter Arrival Time) features
        features.put("Flow IAT Mean", "0");
        features.put("Flow IAT Std", "0");
        features.put("Flow IAT Max", "0");
        features.put("Flow IAT Min", "0");
        features.put("Fwd IAT Total", "0");
        features.put("Fwd IAT Mean", "0");
        features.put("Fwd IAT Std", "0");
        features.put("Fwd IAT Max", "0");
        features.put("Fwd IAT Min", "0");
        features.put("Bwd IAT Total", "0");
        features.put("Bwd IAT Mean", "0");
        features.put("Bwd IAT Std", "0");
        features.put("Bwd IAT Max", "0");
        features.put("Bwd IAT Min", "0");
        
        // TCP flags features
        features.put("Fwd PSH Flags", tcp != null && tcp.optBoolean("tcp_tcp_flags_push", false) ? "1" : "0");
        features.put("Bwd PSH Flags", "0");
        features.put("Fwd URG Flags", tcp != null && tcp.optBoolean("tcp_tcp_flags_urg", false) ? "1" : "0");
        features.put("Bwd URG Flags", "0");
        
        // Header features
        features.put("Fwd Header Length", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_hdr_len", "0") : "0");
        features.put("Bwd Header Length", "0");
        
        // Packet rate features
        features.put("Fwd Packets/s", "0");
        features.put("Bwd Packets/s", "0");
        
        // Packet statistics
        features.put("Min Packet Length", frame != null ? getValueOrDefault(frame, "frame_frame_len", "0") : "0");
        features.put("Max Packet Length", frame != null ? getValueOrDefault(frame, "frame_frame_len", "0") : "0");
        features.put("Packet Length Mean", frame != null ? getValueOrDefault(frame, "frame_frame_len", "0") : "0");
        features.put("Packet Length Std", "0");
        features.put("Packet Length Variance", "0");
        
        // TCP flag counts
        features.put("FIN Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_fin", false) ? "1" : "0");
        features.put("SYN Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_syn", false) ? "1" : "0");
        features.put("RST Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_reset", false) ? "1" : "0");
        features.put("PSH Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_push", false) ? "1" : "0");
        features.put("ACK Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_ack", false) ? "1" : "0");
        features.put("URG Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_urg", false) ? "1" : "0");
        features.put("CWE Flag Count", "0");
        features.put("ECE Flag Count", tcp != null && tcp.optBoolean("tcp_tcp_flags_ece", false) ? "1" : "0");
        
        // Flow ratios
        features.put("Down/Up Ratio", "0");
        
        // Size features
        features.put("Average Packet Size", frame != null ? getValueOrDefault(frame, "frame_frame_len", "0") : "0");
        features.put("Avg Fwd Segment Size", "0");
        features.put("Avg Bwd Segment Size", "0");
        features.put("Fwd Header Length.1", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_hdr_len", "0") : "0");
        
        // Bulk transfer features
        features.put("Fwd Avg Bytes/Bulk", "0");
        features.put("Fwd Avg Packets/Bulk", "0");
        features.put("Fwd Avg Bulk Rate", "0");
        features.put("Bwd Avg Bytes/Bulk", "0");
        features.put("Bwd Avg Packets/Bulk", "0");
        features.put("Bwd Avg Bulk Rate", "0");
        
        // Subflow features
        features.put("Subflow Fwd Packets", "0");
        features.put("Subflow Fwd Bytes", "0");
        features.put("Subflow Bwd Packets", "0");
        features.put("Subflow Bwd Bytes", "0");
        
        // Window size features
        features.put("Init_Win_bytes_forward", tcp != null ? getValueOrDefault(tcp, "tcp_tcp_window_size_value", "0") : "0");
        features.put("Init_Win_bytes_backward", "0");
        
        // Data packet features
        features.put("act_data_pkt_fwd", "0");
        features.put("min_seg_size_forward", "0");
        
        // Timing features
        features.put("Active Mean", "0");
        features.put("Active Std", "0");
        features.put("Active Max", "0");
        features.put("Active Min", "0");
        features.put("Idle Mean", "0");
        features.put("Idle Std", "0");
        features.put("Idle Max", "0");
        features.put("Idle Min", "0");
        
        // Protocol information
        features.put("protocol", String.valueOf(protocolToInt(parseProtocol(layers))));

        // SYN flag specifically
        String flagSyn = "0";
        if (layers.has("tcp_tcp_flags_syn") && layers.getBoolean("tcp_tcp_flags_syn")) {
            flagSyn = "1";
        }
        features.put("flag_syn", flagSyn);

        return features;
    }


    // Determines the protocol used in the packet
    private static String parseProtocol(JSONObject layers) {
        if (layers.has("ip")) return "IP";
        if (layers.has("tcp")) return "TCP";
        if (layers.has("udp")) return "UDP";
        if (layers.has("icmp")) return "ICMP";
        if (layers.has("arp")) return "ARP";
        if (layers.has("ipv6")) return "IPV6";
        if (layers.has("ipv4")) return "IPV4";
        if (layers.has("ethernet")) return "ETHERNET";

        return "UNKNOWN";
    }


    // Retrieves a value under a given key
    private static String getValueOrDefault(JSONObject obj, String key, String defaultValue) {
        try {
            if (obj.has(key)) {
                Object value = obj.get(key);
                if (value instanceof JSONArray) {
                    JSONArray arr = (JSONArray) value;
                    if (arr.length() > 0) {
                        return arr.getString(0);
                    }
                } else {
                    return value.toString();
                }
            }
        } catch (Exception e) {
            logger.log(Level.FINE, "Error getting key " + key, e);
        }
        return defaultValue;
    }
    
    
    // Converts protocol name to numeric value
    private static int protocolToInt(String protocol) {
        switch (protocol) {
            case "IP": return 1;
            case "TCP": return 2;
            case "UDP": return 3;
            case "ICMP": return 4;
            case "ARP": return 5;
            case "IPV6": return 7;
            case "IPV4": return 8;
            case "ETHERNET": return 9;
            default: return 0;
        }
    }
}