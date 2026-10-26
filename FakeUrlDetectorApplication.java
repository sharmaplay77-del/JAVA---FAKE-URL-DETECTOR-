
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FakeUrlDetectorApplication {

    private static final Path REPORT_FILE =
            Paths.get("scam-reports.txt");

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(
                new InetSocketAddress("localhost", 8080), 0);

        // ========================================
        // API 1: Scan URL
        // ========================================

        server.createContext("/api/scan", exchange -> {
            addCorsHeaders(exchange);

            try {
                String method = exchange.getRequestMethod();

                if ("OPTIONS".equalsIgnoreCase(method)) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                if (!"POST".equalsIgnoreCase(method)) {
                    sendJson(exchange, 405,
                            "{\"error\":\"Only POST requests are allowed\"}");
                    return;
                }

                String body = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8);

                Matcher matcher = Pattern.compile(
                        "\"url\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
                        .matcher(body);

                if (!matcher.find()) {
                    sendJson(exchange, 400,
                            "{\"error\":\"Please provide a URL\"}");
                    return;
                }

                String url = unescapeJson(matcher.group(1)).trim();
                String result = analyzeUrl(url);

                if (result.startsWith("{\"error\"")) {
                    sendJson(exchange, 400, result);
                } else {
                    sendJson(exchange, 200, result);
                }

            } catch (Exception e) {
                sendJson(exchange, 400,
                        "{\"error\":\"Invalid request\"}");
            } finally {
                exchange.close();
            }
        });

        // ========================================
        // API 2: Submit AND view scam reports
        // Only ONE /api/reports handler
        // ========================================

        server.createContext("/api/reports", exchange -> {
            addCorsHeaders(exchange);

            try {
                String method = exchange.getRequestMethod();

                // Browser CORS preflight
                if ("OPTIONS".equalsIgnoreCase(method)) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                // GET: Return all saved reports
                if ("GET".equalsIgnoreCase(method)) {

                    List<String> reports = new ArrayList<>();

                    if (Files.exists(REPORT_FILE)) {
                        reports = Files.readAllLines(
                                REPORT_FILE,
                                StandardCharsets.UTF_8);
                    }

                    StringBuilder json = new StringBuilder("[");

                    for (int i = 0; i < reports.size(); i++) {
                        if (i > 0) {
                            json.append(",");
                        }

                        // Each saved report is a JSON object string.
                        json.append(reports.get(i));
                    }

                    json.append("]");

                    sendJson(exchange, 200, json.toString());
                    return;
                }

                // POST: Save a new report
                if ("POST".equalsIgnoreCase(method)) {

                    String body = new String(
                            exchange.getRequestBody().readAllBytes(),
                            StandardCharsets.UTF_8).trim();

                    if (body.isEmpty()) {
                        sendJson(exchange, 400,
                                "{\"error\":\"Report data is required\"}");
                        return;
                    }

                    // Check that the submitted report is valid JSON.
                    if (!body.startsWith("{") || !body.endsWith("}")) {
                        sendJson(exchange, 400,
                                "{\"error\":\"Invalid report format\"}");
                        return;
                    }

                    // Save one report per line.
                    Files.write(
                            REPORT_FILE,
                            (body + System.lineSeparator())
                                    .getBytes(StandardCharsets.UTF_8),
                            StandardOpenOption.CREATE,
                            StandardOpenOption.APPEND
                    );

                    System.out.println(
                            "Scam report saved permanently: " + body);

                    sendJson(exchange, 200,
                            "{\"message\":\"Scam report saved successfully\"}");
                    return;
                }

                sendJson(exchange, 405,
                        "{\"error\":\"Only GET and POST are allowed\"}");

            } catch (Exception e) {
                e.printStackTrace();

                sendJson(exchange, 500,
                        "{\"error\":\"Unable to process scam reports\"}");
            } finally {
                exchange.close();
            }
        });

        // ========================================
        // Start server
        // ========================================

        server.start();

        System.out.println("Fake URL Detector backend started!");
        System.out.println("URL: http://localhost:8080");
        System.out.println("Scan endpoint: http://localhost:8080/api/scan");
        System.out.println("Reports endpoint: http://localhost:8080/api/reports");
        System.out.println("Press Ctrl+C to stop.");
    }

    // ========================================
    // URL ANALYSIS
    // ========================================

    private static String analyzeUrl(String input) {

        List<String> findings = new ArrayList<>();
        int score = 0;

        try {
            URI uri = URI.create(input);
            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme == null
                    || !(scheme.equalsIgnoreCase("http")
                    || scheme.equalsIgnoreCase("https"))
                    || host == null
                    || !host.contains(".")) {

                return "{\"error\":\"Enter a valid HTTP or HTTPS URL\"}";
            }

            if (!scheme.equalsIgnoreCase("https")) {
                score += 10;
                findings.add(
                        "HTTPS is not used. This alone does not mean the URL is fake.");
            }

            if (uri.getRawUserInfo() != null || input.contains("@")) {
                score += 25;
                findings.add(
                        "The URL contains user information or an @ symbol.");
            }

            if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                score += 25;
                findings.add(
                        "The hostname looks like an IPv4 address.");
            }

            if (input.length() > 100) {
                score += 10;
                findings.add("The URL is unusually long.");
            }

            String lower = input.toLowerCase();

            String[] suspiciousWords = {
                    "login", "verify", "account", "password",
                    "banking", "wallet", "free-gift", "claim-prize"
            };

            int keywordScore = 0;
            List<String> matched = new ArrayList<>();

            for (String word : suspiciousWords) {
                if (lower.contains(word)) {
                    keywordScore += 8;
                    matched.add(word);
                }
            }

            if (!matched.isEmpty()) {
                score += Math.min(keywordScore, 24);
                findings.add(
                        "Potentially suspicious keywords: "
                                + String.join(", ", matched));
            }

            long hyphens = host.chars()
                    .filter(c -> c == '-')
                    .count();

            if (hyphens >= 3) {
                score += 10;
                findings.add(
                        "The hostname contains multiple hyphens.");
            }

            score = Math.min(score, 100);

            String status;

            if (score >= 60) {
                status = "High Risk";
            } else if (score >= 30) {
                status = "Medium Risk";
            } else {
                status = "Low Risk";
            }

            if (findings.isEmpty()) {
                findings.add(
                        "No suspicious patterns were detected by these basic rules.");
            }

            findings.add(
                    "This rule-based result cannot guarantee that a website is safe.");

            return "{\"url\":\"" + jsonEscape(input)
                    + "\",\"score\":" + score
                    + ",\"status\":\"" + status
                    + "\",\"findings\":" + listToJson(findings) + "}";

        } catch (Exception e) {
            return "{\"error\":\"Invalid URL format\"}";
        }
    }

    // ========================================
    // JSON HELPERS
    // ========================================

    private static String listToJson(List<String> items) {

        StringBuilder result = new StringBuilder("[");

        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                result.append(",");
            }

            result.append("\"")
                    .append(jsonEscape(items.get(i)))
                    .append("\"");
        }

        return result.append("]").toString();
    }

    private static String jsonEscape(String text) {

        return text.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String unescapeJson(String text) {

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (c == '\\' && i + 1 < text.length()) {
                char next = text.charAt(++i);

                switch (next) {
                    case '"':
                        result.append('"');
                        break;
                    case '\\':
                        result.append('\\');
                        break;
                    case '/':
                        result.append('/');
                        break;
                    case 'n':
                        result.append('\n');
                        break;
                    case 'r':
                        result.append('\r');
                        break;
                    case 't':
                        result.append('\t');
                        break;
                    default:
                        result.append('\\').append(next);
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    // ========================================
    // HTTP HELPERS
    // ========================================

    private static void addCorsHeaders(HttpExchange exchange) {

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Origin", "*");

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Methods", "GET, POST, OPTIONS");

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Headers", "Content-Type");

        exchange.getResponseHeaders().set(
                "Content-Type", "application/json; charset=UTF-8");
    }

    private static void sendJson(
            HttpExchange exchange, int status, String json)
            throws IOException {

        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        exchange.sendResponseHeaders(status, bytes.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}

