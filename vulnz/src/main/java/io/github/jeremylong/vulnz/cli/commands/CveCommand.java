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
import io.github.jeremylong.vulnz.cli.model.CvesNvdPojo;
import io.github.jeremylong.vulnz.cli.ui.IProgressMonitor;
import io.github.jeremylong.vulnz.cli.ui.JlineShutdownHook;
import io.github.jeremylong.vulnz.cli.ui.ProgressMonitor;
import io.prometheus.metrics.core.metrics.Gauge;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import org.apache.commons.io.output.CountingOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.format.DateTimeFormatter;
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
     * Start year (until today) to cache CVEs for.
     */
    private static final int START_YEAR = 2002;

    // TODO - get format and version from API
    private static final String FORMAT = "NVD_CVE";
    private static final String VERSION = "2.0";

    /**
     * Hex code characters used in getHex.
     */
    private static final String HEXES = "0123456789abcdef";

    private static final Gauge CVE_LOAD_COUNTER = Gauge.builder().name("cve_load_counter")
            .help("Total number of loaded cve's").register();
    private static final Gauge CVE_COUNTER = Gauge.builder().name("cve_counter").help("Total number of cached cve's")
            .register();
    public static final int EIGHT_DAYS = 8;

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

    /**
     * For all years, fetch the NVD vulnerabilities and save them each into one cache file.
     */
    private Integer processRequest(NvdCveClientBuilder apiBuilder, CacheProperties properties) {
        // will hold all entries that have been changed within the last 8 days across all years
        List<DefCveItem> recentlyChangedEntries = new ArrayList<>();

        for (int currentYear = START_YEAR; currentYear <= Year.now().getValue(); currentYear++) {

            // Be forgiving, if we fail to fetch a year, we just continue with the next one
            try {
                // reset our filters for each year
                apiBuilder.removeLastModifiedFilter();
                apiBuilder.removePublishDateFilter();

                Path cacheFilePath = buildCacheTargetFileForYear(properties, currentYear);
                LOG.info("INFO *** Processing year {} ***", currentYear);
                CvesNvdPojo existingCacheData = loadExistingCacheAndConfigureApi(apiBuilder, cacheFilePath);
                CvesNvdPojo cvesForYear = aggregateCvesForYear(currentYear, apiBuilder);

                // merge old with new data. It is intended to add old items to the new ones, thus we keep newly fetched
                // items with the same ID from the API, not overriding from old cache
                if (existingCacheData != null) {
                    LOG.info("INFO Fetched #{} updated entries for already existing local cache with #{} entries",
                            cvesForYear.vulnerabilities.size(), existingCacheData.vulnerabilities.size());
                    cvesForYear.vulnerabilities.addAll(existingCacheData.vulnerabilities);
                } else {
                    LOG.info("INFO Fetched #{} new entries for year {}", cvesForYear.vulnerabilities.size(),
                            currentYear);
                }

                if (cvesForYear.lastUpdated != null) {
                    properties.set("lastModifiedDate", cvesForYear.lastUpdated);
                }
                storeEntireYearToCache(currentYear, cvesForYear, properties);
                LOG.info("INFO *** Finished year {} with #{} entries ***", currentYear,
                        cvesForYear.vulnerabilities.size());

                // calculate recently changed entries, means changed within the last 8 days
                recentlyChangedEntries.addAll(extractRecentChangedEntries(cvesForYear));
            } catch (Exception ex) {
                LOG.error("\nERROR processing year {}", currentYear, ex);
                LOG.info("INFO ... continuing with next year");
            }
        }

        recentlyChangedEntries = loadExistingModifiedCache(apiBuilder, properties, recentlyChangedEntries);

        createCacheRecentlyChangedCacheFile(recentlyChangedEntries, properties, ZonedDateTime.now());

        return 0;
    }

    private List<DefCveItem> loadExistingModifiedCache(NvdCveClientBuilder apiBuilder, CacheProperties properties, List<DefCveItem> recentlyChangedEntries) {
        try {
            Path cacheFilePath = buildCacheTargetFileForYear(properties, "modified");
            if (Files.isRegularFile(cacheFilePath)) {
                List<DefCveItem> modified = new ArrayList<>();
                CvesNvdPojo existing = loadExistingCacheAndConfigureApi(apiBuilder, cacheFilePath);
                existing.vulnerabilities.stream()
                        .filter(cve -> ChronoUnit.DAYS.between(cve.getCve().getLastModified(), ZonedDateTime.now()) <= EIGHT_DAYS)
                        .forEach(cve -> modified.add(cve));
                modified.addAll(recentlyChangedEntries);
                recentlyChangedEntries = modified;
            }
        } catch (Exception ex) {
            LOG.error("ERROR processing modified changed entries", ex);
        }
        return recentlyChangedEntries;
    }

    private CvesNvdPojo loadExistingCacheAndConfigureApi(NvdCveClientBuilder apiBuilder, Path cacheFilePath) {
        ZonedDateTime lastUpdateDate = determineExistingCacheFileLastChanged(cacheFilePath);
        if (lastUpdateDate == null) {
            // no existing cache exists - nothing to load and nothing to configure. Fetch the entire year.
            return null;
        }

        // else only fetch entries that have been changed since the last update
        apiBuilder.withLastModifiedFilter(lastUpdateDate, ZonedDateTime.now());
        LOG.info("INFO Found existing local cache '{}'. Cache was created/updated on {}", cacheFilePath.getFileName(),
                lastUpdateDate.format(DateTimeFormatter.RFC_1123_DATE_TIME));
        LOG.info("INFO Only fetching items that have been changed since then from the API");

        // Load existing cache data
        ObjectMapper objectMapper = getCacheObjectMapper();
        try (FileInputStream fis = new FileInputStream(cacheFilePath.toFile());
                GZIPInputStream gzis = new GZIPInputStream(fis)) {
            CveApiJson20 data = objectMapper.readValue(gzis, CveApiJson20.class);
            return new CvesNvdPojo(data.getVulnerabilities(), data.getTimestamp());
        } catch (IOException exception) {
            throw new CacheException("Unable to read cached data: " + cacheFilePath, exception);
        }
    }

    /**
     * Given the year, fetch all vulnerabilities for this year by using a publication date range filter with a maximum
     * range of 120 days (due to NVD api limits). Ensures vulnerabilities are unique and sorted by publishing date, ASC
     */
    private CvesNvdPojo aggregateCvesForYear(int year, NvdCveClientBuilder apiBuilder) {
        // by NVDs API limit, 120 is the max range
        final int MAX_DAYS_RANGE = 115;

        int dayOfYearStart = 1;

        ZonedDateTime yearStart = ZonedDateTime.of(year, 1, 1, 0, 0, 0, 0, ZoneId.systemDefault());
        int yearLengthInDays = Year.from(yearStart).length();
        CvesNvdPojo finalResult = new CvesNvdPojo(new ArrayList<>(), ZonedDateTime.now());
        while (dayOfYearStart < yearLengthInDays) {
            // first day of the year we start from
            ZonedDateTime from = yearStart.plusDays(dayOfYearStart);

            if (from.isAfter(ZonedDateTime.now())) {
                // we are fetching for items in the future, stop here
                break;
            }
            // get the end day of the range, but ensure we do not overshoot
            int dayOfYearEnd = Math.min(dayOfYearStart + MAX_DAYS_RANGE, yearLengthInDays - 1);

            ZonedDateTime to = yearStart.plusDays(dayOfYearEnd)
                    // since we need the end of the day, just pick the next one and reset time to 00:00
                    .plusDays(1).truncatedTo(ChronoUnit.DAYS);
            // apply our range to the API call
            apiBuilder.withPublishedDateFilter(from, to);

            // fetch entries for this range
            CvesNvdPojo currentResult = fetchFromNVDApi(apiBuilder);

            // update our last updated, since we crawl up the year, this will be the most recent in the end
            finalResult.lastUpdated = currentResult.lastUpdated;
            // aggregate all results
            finalResult.vulnerabilities.addAll(currentResult.vulnerabilities);

            // let the next fetch start on the following day we ended on before (since we fetched up to 'to midnight'
            dayOfYearStart = dayOfYearEnd + 1;
        }

        return finalResult;
    }

    /**
     * Given the CVEs for the year, stores all of them in a json cache file and a meta-dat file. creates
     * nvdcve-$year.json.gz and nvdcve-$year.meta
     */
    private void storeEntireYearToCache(int year, CvesNvdPojo cves, CacheProperties properties) {
        ZonedDateTime lastChanged = Objects.requireNonNullElseGet(cves.lastUpdated, ZonedDateTime::now);
        properties.set("lastModifiedDate." + year, lastChanged);
        int size = cves.vulnerabilities.size();

        CveApiJson20 data = new CveApiJson20(size, 0, size, FORMAT, VERSION, lastChanged, cves.vulnerabilities);

        MessageDigest md = getDigestAlg();

        // save vulnerabilities into cache
        final File cacheFile = buildCacheTargetFileForYear(properties, year).toFile();
        long uncompressedSize = saveCacheAsGzip(cacheFile, data, md);

        // save meta data
        final File metaDataFile = buildMetaDataTargetFileForYear(properties, year).toFile();
        saveMetaData(metaDataFile, cacheFile.length(), uncompressedSize, lastChanged, md);
    }

    /**
     * Create cache holding all CVE items that have been changed within the last 8 days. Creates:
     * nvdcve-modified.json.gz and nvdcve-modified.meta
     */
    private void createCacheRecentlyChangedCacheFile(List<DefCveItem> recentlyChanged, CacheProperties properties,
            ZonedDateTime lastChanged) {
        final String prefix = properties.get("prefix", "nvdcve-");
        Path recentChangesCachePath = Path.of(properties.getDirectory().getPath(), prefix + "modified.json.gz");
        int recentSize = recentlyChanged.size();

        CveApiJson20 data = new CveApiJson20(recentSize, 0, recentSize, FORMAT, VERSION, lastChanged, recentlyChanged);

        MessageDigest md = getDigestAlg();

        // create cache file including the CVE entries that recently changed
        File recentCacheFile = recentChangesCachePath.toFile();
        long uncompressedSize = saveCacheAsGzip(recentCacheFile, data, md);
        LOG.info("INFO Stored {} entries in {} as recent changed items across all years",
                data.getVulnerabilities().size(), recentCacheFile.getName());

        // Create meta-file
        Path metaDataFile = Path.of(properties.getDirectory().getPath(), prefix + "modified.meta");
        saveMetaData(metaDataFile.toFile(), recentCacheFile.length(), uncompressedSize, lastChanged, md);
    }

    private long saveCacheAsGzip(File targetFile, CveApiJson20 data, MessageDigest md) {
        final ObjectMapper objectMapper = getCacheObjectMapper();

        long uncompressedSize;
        try (FileOutputStream fileOutputStream = new FileOutputStream(targetFile);
                GZIPOutputStream gzipOutputStream = new GZIPOutputStream(fileOutputStream);
                DigestOutputStream digestOutputStream = new DigestOutputStream(gzipOutputStream, md);
                CountingOutputStream countingOutputStream = new CountingOutputStream(digestOutputStream)) {
            objectMapper.writeValue(countingOutputStream, data);
            uncompressedSize = countingOutputStream.getByteCount();
        } catch (IOException ex) {
            throw new CacheException("Unable to write cached data: " + targetFile, ex);
        }

        return uncompressedSize;
    }

    private ObjectMapper getCacheObjectMapper() {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        if (isPrettyPrint()) {
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        }
        return objectMapper;
    }

    private void saveMetaData(File targetFile, long compressedSize, long uncompressedSize, ZonedDateTime lastChanged,
            MessageDigest md) {
        String checksum = getHex(md.digest());
        try (FileOutputStream fileOutputStream = new FileOutputStream(targetFile);
                OutputStreamWriter osw = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8);
                PrintWriter writer = new PrintWriter(osw)) {
            final String lmd = DateTimeFormatter.ISO_DATE_TIME.format(lastChanged);
            writer.println("lastModifiedDate:" + lmd);
            writer.println("size:" + uncompressedSize);
            writer.println("gzSize:" + compressedSize);
            writer.println("sha256:" + checksum);
        } catch (IOException ex) {
            throw new CacheException("Unable to write cached meta-data: {}" + targetFile.getAbsolutePath(), ex);
        }
    }

    private ZonedDateTime determineExistingCacheFileLastChanged(Path cacheFilePath) {
        File cacheFile = cacheFilePath.toFile();
        if (!cacheFile.exists() || cacheFile.length() == 0) {
            return null;
        }

        return ZonedDateTime.ofInstant(Instant.ofEpochMilli(cacheFile.getAbsoluteFile().lastModified()),
                ZoneId.systemDefault());
    }

    private Path buildCacheTargetFileForYear(CacheProperties properties, String year) {
        return buildCacheTargetFileForYear(properties, Integer.parseInt(year));
    }

    private Path buildCacheTargetFileForYear(CacheProperties properties, int year) {
        final String prefix = properties.get("prefix", "nvdcve-");
        return Path.of(properties.getDirectory().getPath(), prefix + year + ".json.gz");
    }

    private Path buildMetaDataTargetFileForYear(CacheProperties properties, int year) {
        final String prefix = properties.get("prefix", "nvdcve-");
        return Path.of(properties.getDirectory().getPath(), prefix + year + ".meta");
    }

    private List<DefCveItem> extractRecentChangedEntries(CvesNvdPojo cvesForYear) {
        return cvesForYear.vulnerabilities.stream()
                .filter(item -> ChronoUnit.DAYS.between(item.getCve().getLastModified(), ZonedDateTime.now()) <= EIGHT_DAYS)
                .collect(Collectors.toList());
    }

    /**
     * Fetching from the NVD api, paginated (max entries per page). Aggregates all entries of all pages, sorts them by
     * publishing date (ASC) and ensures those are unique.
     */
    private CvesNvdPojo fetchFromNVDApi(NvdCveClientBuilder apiBuilder) {
        // retrieve from NVD API
        try (NvdCveClient api = apiBuilder.build();
                IProgressMonitor monitor = new ProgressMonitor(interactive, "NVD")) {
            Runtime.getRuntime().addShutdownHook(new JlineShutdownHook());

            // we use a set for de-duplication
            Set<DefCveItem> vulnerabilities = new HashSet<>();

            // crawl the api page by page
            while (api.hasNext()) {
                Collection<DefCveItem> data = api.next();
                vulnerabilities.addAll(data);
                if (!data.isEmpty()) {
                    CVE_LOAD_COUNTER.set(data.size());
                    monitor.updateProgress("NVD", (int) CVE_LOAD_COUNTER.get(), api.getTotalAvailable());
                }
            }
            CVE_COUNTER.set(vulnerabilities.size());

            // convert to sorted list by id
            List<DefCveItem> sorted = vulnerabilities.stream().sorted(Comparator.comparing(v -> v.getCve().getId()))
                    .collect(Collectors.toList());
            return new CvesNvdPojo(sorted, api.getLastUpdated());
        } catch (Exception ex) {
            throw new CacheException("Unable to complete NVD cache update due to error: " + ex.getMessage());
        }
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

    private MessageDigest getDigestAlg() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CacheException("Unable to calculate sha256 checksum", e);
        }
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
