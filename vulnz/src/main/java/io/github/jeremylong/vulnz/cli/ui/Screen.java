package io.github.jeremylong.vulnz.cli.ui;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Screen {

    boolean quiet;
    boolean supported;
    Map<String, Integer> rows = new HashMap<>();

    public Screen(boolean quiet) {
        this.quiet = quiet;
        this.supported = isSupported();
    }

    private static void printProgress(String banner, long total, long current) {
        StringBuilder string = new StringBuilder(80);
        int percent = (int) (current * 100 / total);
        string.append("\033[H\033[2J").append(banner);
        if (current >= total) {
            string.append("\n\nComplete");
        } else {
            int completed = percent / 2;
            int remaining = 50 - completed;
            string.append(String.join("", Collections.nCopies(percent == 0 ? 2 : 2 - (int) (Math.log10(percent)), " ")))
                    .append(String.format(" %d%% [", percent))
                    .append(String.join("", Collections.nCopies(completed, "="))).append('>')
                    .append(String.join("", Collections.nCopies(remaining, " "))).append(']')
                    .append(String.join("",
                            Collections.nCopies((int) (Math.log10(total)) - (int) (Math.log10(current)), " ")))
                    .append(String.format(" %d/%d", current, total));
        }
        System.err.print(string);
    }

    public void addRow(String name) {
        this.rows.put(name, 0);
    }

    public void updateProgress(String name, int current, int max) {
        rows.put(name, current / max);
    }

    private boolean isSupported() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("mac") || os.contains("linux");
    }


}
