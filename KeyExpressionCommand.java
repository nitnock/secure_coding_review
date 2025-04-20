package com.pv286.bip380;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;

public class KeyExpressionCommand {
    private static final NetworkParameters params = NetworkParameters.fromID(NetworkParameters.ID_MAINNET);

    public static void parseAndEcho(String[] args) {
        String expr = args[0];
        validateKeyExpression(expr);
        System.out.println(expr);
    }

    static void validateKeyExpression(String expr) {
        int firstBracket = expr.indexOf("[");
        if (firstBracket != -1 && expr.indexOf("[", firstBracket + 1) != -1) {
            throw new IllegalArgumentException("Multiple key origins: " + expr);
        }

        String origin = null;
        String keyAndPath = expr;
        if (expr.startsWith("[") && expr.contains("]")) {
            int endBracket = expr.indexOf("]");
            origin = expr.substring(0, endBracket + 1);
            keyAndPath = expr.substring(endBracket + 1);
            validateOrigin(origin);
        } else if (expr.contains("]") && !expr.startsWith("[")) {
            throw new IllegalArgumentException("Missing key origin start: " + expr);
        } else if (expr.startsWith("[") && !expr.contains("]")) {
            throw new IllegalArgumentException("Unterminated key origin: " + expr);
        }

        int firstSlash = keyAndPath.indexOf("/");
        String keyPart = firstSlash == -1 ? keyAndPath : keyAndPath.substring(0, firstSlash);
        String pathPart = firstSlash == -1 ? null : keyAndPath.substring(firstSlash);

        if (keyPart.isEmpty()) {
            throw new IllegalArgumentException("Key origin with no public key: " + expr);
        }

        if (isHexPublicKey(keyPart)) {
            if (pathPart != null) throw new IllegalArgumentException("Public key cannot have derivation path: " + expr);
        } else if (isWifPrivateKey(keyPart)) {
            if (pathPart != null) {
                if (pathPart.equals("/*")) {
                    throw new IllegalArgumentException("Private key with derivation children: " + expr);
                }
                throw new IllegalArgumentException("Private key with derivation: " + expr);
            }
        } else if (isExtendedKey(keyPart)) {
            if (pathPart != null) validatePath(pathPart, expr);
        } else {
            throw new IllegalArgumentException("Invalid key format: " + expr);
        }
    }

    private static boolean isHexPublicKey(String key) {
        if (!key.matches("[0-9a-fA-F]+")) return false;
        int len = key.length();
        return (len == 66 && (key.startsWith("02") || key.startsWith("03"))) || 
               (len == 130 && key.startsWith("04"));
    }

    private static boolean isWifPrivateKey(String key) {
        try {
            byte[] decoded = Base58.decode(key);
            if (decoded.length != 37 && decoded.length != 38) return false;
            if (decoded[0] != (byte) 0x80) return false;
            int keyLength = decoded.length == 37 ? 32 : 33;
            byte[] keyBytes = new byte[keyLength + 1];
            System.arraycopy(decoded, 0, keyBytes, 0, keyLength + 1);
            byte[] checksum = new byte[4];
            System.arraycopy(decoded, keyLength + 1, checksum, 0, 4);
            byte[] doubleSha = Sha256Hash.hashTwice(keyBytes);
            for (int i = 0; i < 4; i++) {
                if (checksum[i] != doubleSha[i]) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isExtendedKey(String key) {
        try {
            DeterministicKey.deserializeB58(key, params);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void validateOrigin(String origin) {
        if (!origin.startsWith("[") || !origin.endsWith("]")) {
            throw new IllegalArgumentException("Invalid key origin format: " + origin);
        }

        String content = origin.substring(1, origin.length() - 1);
        if (content.isEmpty()) {
            throw new IllegalArgumentException("Empty key origin: " + origin);
        }

        if (content.endsWith("/")) {
            throw new IllegalArgumentException("Trailing slash in key origin: " + origin);
        }

        String[] parts = content.split("/");
        String fingerprint = parts[0];

        if (!fingerprint.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("Non hex fingerprint: " + origin);
        }
        if (fingerprint.length() < 8) {
            throw new IllegalArgumentException("Too short fingerprint: " + origin);
        }
        if (fingerprint.length() > 8) {
            throw new IllegalArgumentException("Too long fingerprint: " + origin);
        }

        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) {
                throw new IllegalArgumentException("Trailing slash in key origin: " + origin);
            }
            if (part.equals("*")) {
                throw new IllegalArgumentException("Children indicator in key origin: " + origin);
            }
            String numStr = part.replaceAll("[hH']$", "");
            if (!numStr.matches("[0-9]+")) {
                throw new IllegalArgumentException("Invalid hardened indicators: " + origin);
            }
            try {
                int num = Integer.parseInt(numStr);
                if (num < 0 ) {
                    throw new IllegalArgumentException("Path index out of range [0, 2^31-1]: " + origin);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid hardened indicators: " + origin);
            }
        }
    }

    private static void validatePath(String path, String expr) {
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException("Invalid derivation path format: " + expr);
        }
        String[] indices = path.split("/");
        for (String index : indices) {
            if (index.isEmpty()) continue;
            if (index.startsWith("*")) {
                if (!index.matches("\\*[hH']?")) {
                    throw new IllegalArgumentException("Invalid hardened indicators: " + expr);
                }
                continue;
            }
            String numStr = index.replaceAll("[hH']$", "");
            if (!numStr.matches("[0-9]+")) {
                throw new IllegalArgumentException("Invalid derivation index: " + expr);
            }
            try {
                long num = Long.parseLong(numStr);
                if (num < 0 || num > (1L << 31) - 1) {
                    throw new IllegalArgumentException("Derivation index out of range: " + expr);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid derivation index: " + expr);
            }
        }
    }
} 