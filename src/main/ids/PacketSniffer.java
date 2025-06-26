package ids;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.logging.*;

import org.json.JSONObject;

public class PacketSniffer {
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private Process process;

    // Starts packet capturing by launching tshark process
    public void startCapture() {
        try {
            // Build the process to run tshark
            logger.info("Starting Tshark...");
            System.out.println("Starting Tshark...");

            // Using NIC (tshark -D)
            ProcessBuilder builder = new ProcessBuilder(
                "tshark",
                "-i", "\\Device\\NPF_{83F29D86-17C5-4644-8D2E-633ABB07AD82}",
                "-l",
                "-p",
                "-T", "ek"
            );

            process = builder.start();
            logger.info("Tshark started");
            System.out.println("Tshark started");

            // Read from tshark line by line
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            logger.info("------------------------------");
            System.out.println("------------------------------");
            
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    if(line.contains("\"layers\"")) {
                        //logger.info("Captured packet JSON: " + line);

                        // Show simplified packet info
                        try {
                            JSONObject obj = new JSONObject(line);
                            JSONObject layers = obj.getJSONObject("layers");
                            /*
                            if (layers.has("eth")) {
                                JSONObject eth = layers.getJSONObject("eth");
                                System.out.println("Ethernet vendor: " + eth.optString("eth_eth_src_oui_resolved"));
                                logger.info("Ethernet vendor: " + eth.optString("eth_eth_src_oui_resolved"));

                            } */
                            if (layers.has("dns")) {
                                JSONObject dns = layers.getJSONObject("dns");
                                System.out.println("DNS Query: " + dns.optString("dns_dns_qry_name"));
                                logger.info("DNS Query: " + dns.optString("dns_dns_qry_name"));
                            }
                            if (layers.has("ip")) {
                                JSONObject ip = layers.getJSONObject("ip");
                                System.out.println("IP src: " + ip.optString("ip_ip_src"));
                                System.out.println("IP dst: " + ip.optString("ip_ip_dst"));
                                logger.info("IP src: " + ip.optString("ip_ip_src"));
                                logger.info("IP dst: " + ip.optString("ip_ip_dst"));
                            }
                            if (layers.has("tcp")) {
                                JSONObject tcp = layers.getJSONObject("tcp");
                                System.out.println("Protocol: TCP");
                                System.out.println("Source port: " + tcp.optString("tcp_tcp_srcport"));
                                System.out.println("Destination port: " + tcp.optString("tcp_tcp_dstport"));
                                logger.info("Protocol: TCP");
                                logger.info("Source port: " + tcp.optString("tcp_tcp_srcport"));
                                logger.info("Destination port: " + tcp.optString("tcp_tcp_dstport"));
                            }
                            if (layers.has("udp")) {
                                JSONObject udp = layers.getJSONObject("udp");
                                System.out.println("Protocol: UDP");
                                System.out.println("Source port: " + udp.optString("udp_udp_srcport"));
                                System.out.println("Destination port: " + udp.optString("udp_udp_dstport"));
                                logger.info("Protocol: UDP");
                                logger.info("Source port: " + udp.optString("udp_udp_srcport"));
                                logger.info("Destination port: " + udp.optString("udp_udp_dstport"));
                            }
                            if (layers.has("http")) {
                                JSONObject http = layers.getJSONObject("http");
                                System.out.println("HTTP Host: " + http.optString("http_host"));
                                System.out.println("HTTP URI: " + http.optString("http_request_uri"));
                                logger.info("HTTP Host: " + http.optString("http_host"));
                                logger.info("HTTP URI: " + http.optString("http_request_uri"));
                            }
                        } catch (Exception e) {
                            System.out.println("Could not simplify packet: " + e.getMessage());
                        }

                        handlePacket(line);
                        logger.info("------------------------------");
                        System.out.println("------------------------------");
                    }
                } else {
                    logger.log(Level.FINE, "Failed to extract features, not a valid packet: " + line); 
                }             
            }
        } catch (IOException e) {
            // Error handling when starting tshark
            System.err.println("Error starting tshark: " + e.getMessage());
        }
    }

    // Stops packet capturing
    public void stopCapture() {
        if (process != null) {
            process.destroy();
        }
    }

    // Extract features and predict if attack
    public void handlePacket(String rawData) {
        Map<String, String> features = FeatureExtractor.extract(rawData);
        boolean isAttack = Predictor.predict(features);
        if (isAttack) {
            logger.log(Level.WARNING, "ATACK!!!!"); 
            AlertManager.raiseAlert(features);
        }
    }

}
