package com.pv286.bip380;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScriptExpressionCommand {
    private static final String INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    private static final String CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final long[] GENERATOR = {0xf5dee51989L, 0xa9fdca3312L, 0x1bab10e32dL, 0x3706b1677aL, 0x644d626ffdL};

    public static void process(String[] args, boolean verifyChecksum, boolean computeChecksum) {
        String expr = args[0];
        int hashIndex = expr.indexOf("#");
        String script = hashIndex == -1 ? expr : expr.substring(0, hashIndex);
        String providedChecksum = hashIndex == -1 ? null : expr.substring(hashIndex + 1);

        if (verifyChecksum) {
            if (providedChecksum == null) {
                throw new IllegalArgumentException(expr + " (no checksum present)");
            }
            if (providedChecksum.isEmpty()) {
                throw new IllegalArgumentException(expr + " (missing checksum)");
            }
            if (providedChecksum.length() < 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                throw new IllegalArgumentException("Too Short Checksum (" + providedChecksum.length() + " chars): must be 8 characters from " + CHECKSUM_CHARSET);
            } else if (providedChecksum.length() > 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                throw new IllegalArgumentException("Too Long Checksum (" + providedChecksum.length() + " chars): must be 8 characters from " + CHECKSUM_CHARSET);
            } else if (providedChecksum.length() == 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                throw new IllegalArgumentException("Invalid checksum format: must be 8 characters from " + CHECKSUM_CHARSET);
            }
            validateScript(script);
            if (!verifyChecksum(script, providedChecksum)) {
                throw new IllegalArgumentException("Error in payload: " + expr);
            }
            System.out.println("OK");
        } else if (computeChecksum) {
            validateScript(script);
            String newChecksum = computeChecksum(script);
            System.out.println(script + "#" + newChecksum);
        } else {
            if (providedChecksum != null) {
                if (providedChecksum.length() < 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                    throw new IllegalArgumentException("Too Short Checksum (" + providedChecksum.length() + " chars): must be 8 characters from " + CHECKSUM_CHARSET);
                } else if (providedChecksum.length() > 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                    throw new IllegalArgumentException("Too Long Checksum (" + providedChecksum.length() + " chars): must be 8 characters from " + CHECKSUM_CHARSET);
                } else if (providedChecksum.length() == 8 && !providedChecksum.matches("[" + CHECKSUM_CHARSET + "]{8}")) {
                    throw new IllegalArgumentException("Invalid checksum format: must be 8 characters from " + CHECKSUM_CHARSET);
                }
                validateScript(script);
                if (!verifyChecksum(script, providedChecksum)) {
                    throw new IllegalArgumentException("Error in payload: " + expr);
                }
            } else {
                validateScript(script);
            }
            System.out.println(expr);
        }
    }

    private static void validateScript(String script) {
        String trimmed = script.replaceAll("[ \t]+", " ").trim();
        if (trimmed.matches("pk\\([^)]+\\)")) {
            validateKeyInScript(trimmed, "pk");
        } else if (trimmed.matches("pkh\\([^)]+\\)")) {
            validateKeyInScript(trimmed, "pkh");
        } else if (trimmed.matches("multi\\(\\d+,[^)]+\\)")) {
            validateMulti(trimmed);
        } else if (trimmed.matches("sh\\(pk\\([^)]+\\)\\)")) {
            validateKeyInScript(trimmed.substring(3, trimmed.length() - 1), "pk");
        } else if (trimmed.matches("sh\\(pkh\\([^)]+\\)\\)")) {
            validateKeyInScript(trimmed.substring(3, trimmed.length() - 1), "pkh");
        } else if (trimmed.matches("sh\\(multi\\(\\d+,[^)]+\\)\\)")) {
            validateMulti(trimmed);
        } else if (trimmed.matches("raw\\([ 0-9a-fA-F]+\\)")) {
            String hexContent = trimmed.substring(4, trimmed.length() - 1).replaceAll("\\s+", "");
            if (!hexContent.matches("[0-9a-fA-F]+")) {
                throw new IllegalArgumentException(script + " (invalid characters in payload)");
            }
        } else {
            throw new IllegalArgumentException(script + " (invalid script expression format)");
        }
    }

    private static void validateKeyInScript(String script, String prefix) {
        String key = script.substring(prefix.length() + 1, script.length() - 1).trim();
        KeyExpressionCommand.validateKeyExpression(key);
    }

    private static void validateMulti(String script) {
        Pattern pattern = Pattern.compile("multi\\((\\d+),([^)]+)\\)");
        Matcher matcher = pattern.matcher(script);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(script + " (invalid multi format)");
        }
        int k = Integer.parseInt(matcher.group(1));
        String[] keys = matcher.group(2).split(",");
        int n = keys.length;
        if (k <= 0 || k > n) {
            throw new IllegalArgumentException(script + " (invalid k in multi: must be 0 < k <= n)");
        }
        for (String key : keys) {
            KeyExpressionCommand.validateKeyExpression(key.trim());
        }
    }

    private static boolean verifyChecksum(String script, String checksum) {
        List<Integer> symbols = descsumExpand(script);
        for (char c : checksum.toCharArray()) {
            int value = CHECKSUM_CHARSET.indexOf(c);
            if (value == -1) return false;
            symbols.add(value);
        }
        long polymod = descsumPolymod(symbols);
        return polymod == 1;
    }

    private static String computeChecksum(String script) {
        List<Integer> symbols = descsumExpand(script);
        for (int i = 0; i < 8; i++) {
            symbols.add(0); // Placeholder for checksum
        }
        long checksumPolymod = descsumPolymod(symbols) ^ 1;
        char[] checksum = new char[8];
        for (int i = 0; i < 8; i++) {
            int value = (int)((checksumPolymod >>> (5 * (7 - i))) & 31);
            checksum[i] = CHECKSUM_CHARSET.charAt(value);
        }
        return new String(checksum);
    }

    private static List<Integer> descsumExpand(String s) {
        List<Integer> symbols = new ArrayList<>();
        List<Integer> groups = new ArrayList<>();
        for (char c : s.toCharArray()) {
            int v = INPUT_CHARSET.indexOf(c);
            if (v == -1) {
                throw new IllegalArgumentException("Invalid character in script: " + c);
            }
            symbols.add(v & 31); // Low 5 bits
            groups.add(v >> 5);  // Group
            if (groups.size() == 3) {
                symbols.add(groups.get(0) * 9 + groups.get(1) * 3 + groups.get(2));
                groups.clear();
            }
        }
        if (groups.size() == 1) {
            symbols.add(groups.get(0));
        } else if (groups.size() == 2) {
            symbols.add(groups.get(0) * 3 + groups.get(1));
        }
        return symbols;
    }

    private static long descsumPolymod(List<Integer> symbols) {
        long chk = 1;
        for (int value : symbols) {
            long top = chk >>> 35;
            chk = ((chk & 0x7ffffffffL) << 5) ^ value;
            for (int i = 0; i < 5; i++) {
                if (((top >>> i) & 1) != 0) {
                    chk ^= GENERATOR[i];
                }
            }
        }
        return chk;
    }
}
