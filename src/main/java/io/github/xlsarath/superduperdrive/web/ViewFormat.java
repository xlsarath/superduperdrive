package io.github.xlsarath.superduperdrive.web;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/** Formatting helpers for templates, exposed as {@code @viewFormat}. */
@Component("viewFormat")
public class ViewFormat {

    private static final DateTimeFormatter INSTANT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC);
    private static final String[] UNITS = {"B", "KB", "MB", "GB", "TB"};

    public String bytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < UNITS.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format(Locale.ROOT, "%.1f %s", value, UNITS[unit]);
    }

    public String instant(Instant instant) {
        return instant == null ? "" : INSTANT.format(instant);
    }
}
