/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022-2025 Jeremy Long. All Rights Reserved.
 */
package io.github.jeremylong.vulnz.cli.commands;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.diogonunes.jcolor.Attribute;
import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.CveApiJson20;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
import io.github.jeremylong.vulnz.cli.cache.CacheException;
import io.github.jeremylong.vulnz.cli.cache.CacheProperties;
import io.github.jeremylong.vulnz.cli.model.BasicOutput;
import io.github.jeremylong.vulnz.cli.ui.IProgressMonitor;
import io.github.jeremylong.vulnz.cli.ui.JlineShutdownHook;
import io.github.jeremylong.vulnz.cli.ui.ProgressMonitor;
import io.prometheus.metrics.core.metrics.Gauge;
import it.unimi.dsi.fastutil.objects.Object2ObjectMap;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import org.apache.commons.io.output.CountingOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Year;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.diogonunes.jcolor.Ansi.colorize;

@Component
@CommandLine.Command(name = "cve", description = "Client for the NVD Vulnerability API")
public class CveCommand extends AbstractNvdCommand {
    /**
     * Reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(CveCommand.class);
    /**
     * Hex code characters used in getHex.
     */
    private static final String HEXES = "0123456789abcdef";

    private static final Gauge CVE_LOAD_COUNTER = Gauge.builder().name("cve_load_counter")
            .help("Total number of loaded cve's").register();
    private static final Gauge CVE_COUNTER = Gauge.builder().name("cve_counter").help("Total number of cached cve's")
            .register();

    @CommandLine.ArgGroup(exclusive = true)
    ConfigGroup configGroup;

    @CommandLine.ArgGroup(exclusive = false)
    PublishedRange publishedRange;
    @CommandLine.ArgGroup(exclusive = false)
    VirtualMatch virtualMatch;
    @CommandLine.Option(names = {"--cpeName"}, description = "")
    private String cpeName;
    @CommandLine.Option(names = {"--cveId"}, description = "The CVE ID")
    private String cveId;
    @CommandLine.Option(names = {"--cvssV2Metrics"}, description = "")
    private String cvssV2Metrics;
    @CommandLine.Option(names = {"--cvssV3Metrics"}, description = "")
    private String cvssV3Metrics;
    @CommandLine.Option(names = {"--keywordExactMatch"}, description = "")
    private String keywordExactMatch;
    @CommandLine.Option(names = {"--keywordSearch"}, description = "")
    private String keywordSearch;
    @CommandLine.Option(names = {"--hasCertAlerts"}, description = "")
    private boolean hasCertAlerts;
    @CommandLine.Option(names = {"--noRejected"}, defaultValue = "false", description = "")
    private boolean noRejected;
    @CommandLine.Option(names = {"--hasCertNotes"}, description = "")
    private boolean hasCertNotes;
    @CommandLine.Option(names = {"--hasKev"}, description = "")
    private boolean hasKev;
    @CommandLine.Option(names = {"--hasOval"}, description = "")
    private boolean hasOval;
    @CommandLine.Option(names = {"--isVulnerable"}, description = "")
    private boolean isVulnerable;
    @CommandLine.Option(names = {"--cvssV2Severity"}, description = "")
    private NvdCveClientBuilder.CvssV2Severity cvssV2Severity;
    @CommandLine.Option(names = {"--cvssV3Severity"}, description = "")
    private NvdCveClientBuilder.CvssV3Severity cvssV3Severity;
    @CommandLine.Option(names = {"--interactive"}, description = "Displays a progress bar")
    private boolean interactive;

    public File getCacheDirectory() {
        if (configGroup != null && configGroup.cacheSettings != null) {
            return configGroup.cacheSettings.directory;
        } else {
            return null;
        }
    }

    @Override
    public Integer timedCall() throws Exception {
        if (isDebug()) {
            LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
            loggerContext.getLogger("io.github.jeremylong").setLevel(Level.DEBUG);
        }
        String apiKey = getApiKey();
        if (apiKey == null || apiKey.isEmpty()) {
            LOG.info("NVD_API_KEY not found. Supply an API key for more generous rate limits");
            apiKey = null;// in case it is empty
        }
        NvdCveClientBuilder builder = NvdCveClientBuilder.aNvdCveApi().withApiKey(apiKey);
        if (getDelay() > 0) {
            builder.withDelay(getDelay());
        }
        if (getMaxRetry() > 0) {
            builder.withMaxRetryCount(getMaxRetry());
        }
        if (cveId != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.CVE_ID, cveId);
        }
        if (cpeName != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.CPE_NAME, cpeName);
        }
        if (cvssV2Metrics != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.CVSS_V2_METRICS, cvssV2Metrics);
        }
        if (cvssV3Metrics != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.CVSS_V3_METRICS, cvssV3Metrics);
        }
        if (keywordExactMatch != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.KEYWORD_EXACT_MATCH, keywordExactMatch);
        }
        if (keywordSearch != null) {
            builder.withFilter(NvdCveClientBuilder.Filter.KEYWORD_SEARCH, keywordSearch);
        }
        if (hasCertAlerts) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.HAS_CERT_ALERTS);
        }
        if (noRejected) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.NO_REJECTED);
        }
        if (hasCertNotes) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.HAS_CERT_NOTES);
        }
        if (hasKev) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.HAS_KEV);
        }
        if (hasOval) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.HAS_OVAL);
        }
        if (isVulnerable) {
            builder.withFilter(NvdCveClientBuilder.BooleanFilter.IS_VULNERABLE);
        }
        if (cvssV2Severity != null) {
            builder.withCvssV2SeverityFilter(cvssV2Severity);
        }
        if (cvssV3Severity != null) {
            builder.withCvssV3SeverityFilter(cvssV3Severity);
        }
        if (publishedRange != null && publishedRange.pubStartDate != null && publishedRange.pubEndDate != null) {
            builder.withPublishedDateFilter(publishedRange.pubStartDate, publishedRange.pubEndDate);
        }

        if (virtualMatch != null && virtualMatch.virtualMatchString != null) {
            builder.withVirtualMatchString(virtualMatch.virtualMatchString);
            if (virtualMatch.matchStart != null && virtualMatch.matchStart.versionStart != null) {
                if (virtualMatch.matchStart.versionStartType != null) {
                    builder.withVersionStart(virtualMatch.matchStart.versionStart,
                            virtualMatch.matchStart.versionStartType);
                } else {
                    builder.withVersionStart(virtualMatch.matchStart.versionStart);
                }
            }

            if (virtualMatch.matchEnd != null && virtualMatch.matchEnd.versionEnd != null) {
                if (virtualMatch.matchEnd.versionEndType != null) {
                    builder.withVersionStart(virtualMatch.matchEnd.versionEnd, virtualMatch.matchEnd.versionEndType);
                } else {
                    builder.withVersionStart(virtualMatch.matchEnd.versionEnd);
                }
            }
        }

        int recordCount = getRecordsPerPage();
        if (recordCount > 0 && recordCount <= 2000) {
            builder.withResultsPerPage(recordCount);
        }
        if (getPageCount() > 0) {
            builder.withMaxPageCount(getPageCount());
        }
        if (getThreads() > 0) {
            builder.withThreadCount(getThreads());
        }

        if (configGroup != null && configGroup.cacheSettings != null) {
            CacheProperties properties = new CacheProperties(configGroup.cacheSettings.directory);
            if (properties.has("lastModifiedDate")) {
                ZonedDateTime start = properties.getTimestamp("lastModifiedDate");
                ZonedDateTime end = start.minusDays(-120);
                if (end.compareTo(ZonedDateTime.now()) > 0) {
                    builder.withLastModifiedFilter(start, end);
                } else {
                    LOG.warn(
                            "Requesting the entire set of NVD CVE data via the api as the cache was last updated over 120 days ago");
                }
            }
            if (configGroup.cacheSettings.prefix != null) {
                properties.set("prefix", configGroup.cacheSettings.prefix);
            }
            try {
                int status = processRequest(builder, properties);
                properties.save();
                return status;
            } catch (CacheException ex) {
                LOG.error(ex.getMessage(), ex);
            }
            return 1;
        }
        if (configGroup != null && configGroup.modifiedRange != null
                && configGroup.modifiedRange.lastModStartDate != null) {
            ZonedDateTime end = configGroup.modifiedRange.lastModEndDate;
            if (end == null) {
                end = configGroup.modifiedRange.lastModStartDate.minusDays(-120);
            }
            builder.withLastModifiedFilter(configGroup.modifiedRange.lastModStartDate, end);
        }
        return processRequest(builder);
    }

    private Integer processRequest(NvdCveClientBuilder builder, CacheProperties properties) {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        if (isPrettyPrint()) {
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        }
        final Object2ObjectOpenHashMap<String, Object2ObjectOpenHashMap<String, DefCveItem>> cves = new Object2ObjectOpenHashMap<>();
        populateKeys(cves);

        ZonedDateTime lastModified = downloadAllUpdates(builder, cves);
        if (lastModified != null) {
            properties.set("lastModifiedDate", lastModified);
        }
        // update cache
        // todo - get format and version from API
        final String format = "NVD_CVE";
        final String version = "2.0";
        final String prefix = properties.get("prefix", "nvdcve-");

        for (Object2ObjectMap.Entry<String, Object2ObjectOpenHashMap<String, DefCveItem>> entry : cves
                .object2ObjectEntrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            final File file = new File(properties.getDirectory(), prefix + entry.getKey() + ".json.gz");
            final File meta = new File(properties.getDirectory(), prefix + entry.getKey() + ".meta");
            final Object2ObjectOpenHashMap<String, DefCveItem> yearData;

            // Load existing year data if present
            if (file.isFile()) {
                yearData = new Object2ObjectOpenHashMap<>();
                try (FileInputStream fis = new FileInputStream(file); GZIPInputStream gzis = new GZIPInputStream(fis)) {
                    CveApiJson20 data = objectMapper.readValue(gzis, CveApiJson20.class);
                    boolean isYearData = !"modified".equals(entry.getKey());
                    // filter the "modified" data to load only the last 7 days of data
                    data.getVulnerabilities().stream().filter(cve -> isYearData
                            || ChronoUnit.DAYS.between(cve.getCve().getLastModified(), ZonedDateTime.now()) <= 7)
                            .forEach(cve -> yearData.put(cve.getCve().getId(), cve));
                } catch (IOException exception) {
                    throw new CacheException("Unable to read cached data: " + file, exception);
                }
                yearData.putAll(entry.getValue());
            } else {
                yearData = entry.getValue();
            }

            List<DefCveItem> vulnerabilities = new ArrayList<DefCveItem>(yearData.values());
            vulnerabilities.sort((v1, v2) -> {
                return v1.getCve().getId().compareTo(v2.getCve().getId());
            });
            ZonedDateTime timestamp;
            Optional<ZonedDateTime> maxDate = vulnerabilities.stream().map(v -> v.getCve().getLastModified())
                    .max(ZonedDateTime::compareTo);
            if (maxDate.isPresent()) {
                timestamp = maxDate.get();
            } else if (lastModified != null) {
                timestamp = lastModified;
            } else {
                timestamp = ZonedDateTime.now();
            }
            properties.set("lastModifiedDate." + entry.getKey(), timestamp);
            CveApiJson20 data = new CveApiJson20(vulnerabilities.size(), 0, vulnerabilities.size(), format, version,
                    timestamp, vulnerabilities);
            MessageDigest md;
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new CacheException("Unable to calculate sha256 checksum", e);
            }
            long byteCount = 0;
            try (FileOutputStream fileOutputStream = new FileOutputStream(file);
                    GZIPOutputStream gzipOutputStream = new GZIPOutputStream(fileOutputStream);
                    DigestOutputStream digestOutputStream = new DigestOutputStream(gzipOutputStream, md);
                    CountingOutputStream countingOutputStream = new CountingOutputStream(digestOutputStream)) {
                objectMapper.writeValue(countingOutputStream, data);
                byteCount = countingOutputStream.getByteCount();
            } catch (IOException ex) {
                throw new CacheException("Unable to write cached data: " + file, ex);
            }
            String checksum = getHex(md.digest());
            try (FileOutputStream fileOutputStream = new FileOutputStream(meta);
                    OutputStreamWriter osw = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8);
                    PrintWriter writer = new PrintWriter(osw)) {
                final String lmd = DateTimeFormatter.ISO_DATE_TIME.format(timestamp);
                writer.println("lastModifiedDate:" + lmd);
                writer.println("size:" + byteCount);
                writer.println("gzSize:" + file.length());
                writer.println("sha256:" + checksum);
            } catch (IOException ex) {
                throw new CacheException("Unable to write cached meta-data: " + file, ex);
            }
        }
        return 0;
    }

    private static void populateKeys(
            Object2ObjectOpenHashMap<String, Object2ObjectOpenHashMap<String, DefCveItem>> cves) {
        cves.put("modified", new Object2ObjectOpenHashMap<>());
        for (int i = 2002; i <= Year.now().getValue(); i++) {
            cves.put(Integer.toString(i), new Object2ObjectOpenHashMap<>());
        }
    }

    private ZonedDateTime downloadAllUpdates(NvdCveClientBuilder builder,
            Object2ObjectOpenHashMap<String, Object2ObjectOpenHashMap<String, DefCveItem>> cves) {
        ZonedDateTime lastModified = null;
        int count = 0;
        // retrieve from NVD API
        try (NvdCveClient api = builder.build(); IProgressMonitor monitor = new ProgressMonitor(interactive, "NVD")) {
            Runtime.getRuntime().addShutdownHook(new JlineShutdownHook());
            while (api.hasNext()) {
                Collection<DefCveItem> data = api.next();
                collectCves(cves, data);
                lastModified = api.getLastUpdated();
                count += data.size();
                CVE_LOAD_COUNTER.set(count);
                monitor.updateProgress("NVD", count, api.getTotalAvailable());
            }
        } catch (Exception ex) {
            LOG.debug("\nERROR", ex);
            throw new CacheException("Unable to complete NVD cache update due to error: " + ex.getMessage());
        }
        CVE_COUNTER.set(cves.values().stream().mapToLong(Object2ObjectOpenHashMap::size).sum());
        return lastModified;
    }

    /**
     * <p>
     * Converts a byte array into a hex string.
     * </p>
     *
     * <p>
     * This method was copied from
     * <a href="http://www.rgagnon.com/javadetails/java-0596.html">http://www.rgagnon.com/javadetails/java-0596.html</a>
     * </p>
     *
     * @param raw a byte array
     * @return the hex representation of the byte array
     */
    public static String getHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt(b & 0x0F));
        }
        return hex.toString();
    }

    private void collectCves(Object2ObjectOpenHashMap<String, Object2ObjectOpenHashMap<String, DefCveItem>> cves,
            Collection<DefCveItem> vulnerabilities) {
        for (DefCveItem item : vulnerabilities) {
            cves.get(getNvdYear(item)).put(item.getCve().getId(), item);
            if (ChronoUnit.DAYS.between(item.getCve().getLastModified(), ZonedDateTime.now()) <= 7) {
                cves.get("modified").put(item.getCve().getId(), item);
            }
        }
    }

    private String getNvdYear(DefCveItem item) {
        int year = item.getCve().getPublished().getYear();
        if (year < 2002) {
            year = 2002;
        }
        return Integer.toString(year);
    }

    private int processRequest(NvdCveClientBuilder builder) throws IOException {
        JsonGenerator jsonOut = getJsonGenerator();
        int status = 1;
        jsonOut.writeStartObject();
        jsonOut.writeFieldName("cves");
        jsonOut.writeStartArray();
        BasicOutput output = new BasicOutput();
        int count = 0;
        try (NvdCveClient api = builder.build(); IProgressMonitor monitor = new ProgressMonitor(interactive, "NVD")) {
            Runtime.getRuntime().addShutdownHook(new JlineShutdownHook());
            while (api.hasNext()) {
                Collection<DefCveItem> list = api.next();
                if (list != null) {
                    count += list.size();
                }
                monitor.updateProgress("NVD", count, api.getTotalAvailable());
                if (list != null) {
                    output.setSuccess(true);
                    output.addCount(list.size());
                    for (DefCveItem c : list) {
                        jsonOut.writeObject(c.getCve());
                    }
                    if (output.getLastModifiedDate() == null
                            || output.getLastModifiedDate().compareTo(api.getLastUpdated()) < 0) {
                        output.setLastModifiedDate(api.getLastUpdated());
                    }
                } else {
                    output.setSuccess(false);
                    output.setReason(String.format("Received HTTP Status Code: %s", api.getLastStatusCode()));
                }
            }
            jsonOut.writeEndArray();
            jsonOut.writeObjectField("results", output);
            jsonOut.writeEndObject();
            jsonOut.close();

            if (!output.isSuccess()) {
                String msg = String.format("%nFAILED: %s", output.getReason());
                LOG.info(colorize(msg, Attribute.RED_TEXT()));
                status = 2;
            }
            LOG.info(colorize("\nSUCCESS", Attribute.GREEN_TEXT()));
            status = 0;
        } catch (Throwable ex) {
            LOG.error("\nERROR", ex);
        }
        return status;
    }

    private JsonGenerator getJsonGenerator() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        JsonFactory jfactory = objectMapper.getFactory();
        // JsonFactory jfactory = new JsonFactory();
        JsonGenerator jsonOut = jfactory.createGenerator(System.out, JsonEncoding.UTF8);
        if (isPrettyPrint()) {
            jsonOut.useDefaultPrettyPrinter();
        }
        return jsonOut;
    }

    static class VirtualMatch {
        @CommandLine.Option(names = {"--virtualMatchString"}, required = true, description = "")
        private String virtualMatchString;

        @CommandLine.ArgGroup(exclusive = false)
        private VirtualMatchStart matchStart;

        @CommandLine.ArgGroup(exclusive = false)
        private VirtualMatchEnd matchEnd;

    }

    static class VirtualMatchEnd {
        @CommandLine.Option(names = {"--versionEnd"}, required = true, description = "")
        private String versionEnd;

        @CommandLine.Option(names = {"--versionEndType"}, description = "INCLUDING or EXCLUDING")
        private NvdCveClientBuilder.VersionType versionEndType;
    }

    static class VirtualMatchStart {
        @CommandLine.Option(names = {"--versionStart"}, required = true, description = "")
        private String versionStart;

        @CommandLine.Option(names = {"--versionStartType"}, description = "INCLUDING or EXCLUDING")
        private NvdCveClientBuilder.VersionType versionStartType;
    }

    static class ModifiedRange {
        @CommandLine.Option(names = "--lastModStartDate", required = true, description = "")
        ZonedDateTime lastModStartDate;
        @CommandLine.Option(names = "--lastModEndDate", description = "")
        ZonedDateTime lastModEndDate;
    }

    static class PublishedRange {
        @CommandLine.Option(names = "--pubStartDate", required = true)
        ZonedDateTime pubStartDate;
        @CommandLine.Option(names = "--pubEndDate", required = true)
        ZonedDateTime pubEndDate;
    }

    static class CacheSettings {
        @CommandLine.Option(names = "--prefix", required = false, description = "The cache file prefix", defaultValue = "nvdcve-")
        public String prefix;
        @CommandLine.Option(names = "--cache", required = true, arity = "0")
        boolean cache;
        @CommandLine.Option(names = "--directory", required = true)
        File directory;
    }

    static class ConfigGroup {
        @CommandLine.ArgGroup(exclusive = false)
        CacheSettings cacheSettings;
        @CommandLine.ArgGroup(exclusive = false)
        ModifiedRange modifiedRange;
    }
}
