package com.example;

public final class Probe implements Runnable {
    public static final String URL = "https://probe.example/v1\n";
    private transient int[][] grid;

    public Probe(int n) { grid = new int[n][n]; }

    public void run() {}

    protected static synchronized long sum(String[] parts, double scale) { return parts.length; }

    public interface Listener { void on(Probe p); }

    enum Mode { A, B }
}
