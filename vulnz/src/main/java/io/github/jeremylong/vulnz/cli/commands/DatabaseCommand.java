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
 * Copyright (c) 2022-2023 Jeremy Long. All Rights Reserved.
 */
package io.github.jeremylong.vulnz.cli.commands;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import io.github.jeremylong.openvulnerability.Configuration;
import io.github.jeremylong.openvulnerability.VulnerabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import static io.github.jeremylong.openvulnerability.Configuration.KEY.CONNECTION_STRING;
import static io.github.jeremylong.openvulnerability.Configuration.KEY.GHSA_TOKEN;
import static io.github.jeremylong.openvulnerability.Configuration.KEY.NVD_API_KEY;
import static io.github.jeremylong.openvulnerability.Configuration.KEY.NVD_CPE_FILTER;
import static io.github.jeremylong.openvulnerability.Configuration.KEY.PROCESS_GHSA;
import static io.github.jeremylong.openvulnerability.Configuration.KEY.PROCESS_NVD;

@Component
@CommandLine.Command(name = "database", description = "Builds a vulnerability database from freely available data sources")
public class DatabaseCommand extends AbstractJsonCommand {
    /**
     * Reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(DatabaseCommand.class);

    @CommandLine.Option(names = {"--endpoint"}, description = "The GraphQL endpoint of GH or GHE")
    private boolean endpoint;

    @CommandLine.Option(names = {
            "--skipGHSA"}, defaultValue = "false", description = "If present the GitHub Security Advisories will not be retrieved and stored.")
    private boolean skipGHSA;

    @CommandLine.Option(names = {
            "--skipNVD"}, defaultValue = "false", description = "If present the NVD CVEs will not be retrieved and stored.")
    private boolean skipNVD;

    @CommandLine.Option(names = {
            "--nvdCPEFilter"}, description = "Filter the NVD data for specific CPEs; generally used to only obtain application CPEs by supplying: cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
    private String nvdCPEFilter;

    // yes - these should not be a string, but seriously down the call path the HttpClient
    // doesn't support passing a header in as a char[]...
    private String ghsaToken = null;
    private String nvdKey = null;

    public static File urlToFile(final String url) {
        String path = url;
        if (path.startsWith("jar:")) {
            // remove "jar:" prefix and "!/" suffix
            final int index = path.indexOf("!/");
            path = path.substring(4, index);
        }
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win") && path.matches("file:[A-Za-z]:.*")) {
                path = "file:/" + path.substring(5);
            }
            return new File(new URL(path).toURI());
        } catch (final MalformedURLException e) {
            // NB: URL is not completely well-formed.
        } catch (final URISyntaxException e) {
            // NB: URL is not completely well-formed.
        }
        if (path.startsWith("file:")) {
            // pass through the URL as-is, minus "file:" prefix
            path = path.substring(5);
            return new File(path);
        }
        throw new IllegalArgumentException("Invalid URL: " + url);
    }

    /**
     * Returns the GitHub API Token Key if supplied.
     *
     * @return the GitHub API Token Key if supplied; otherwise <code>null</code>
     */
    protected String getGhsaToken() {
        if (ghsaToken == null && System.getenv("GITHUB_TOKEN") != null) {
            String token = System.getenv("GITHUB_TOKEN");
            if (token != null && token.startsWith("op://")) {
                LOG.warn(
                        "GITHUB_TOKEN begins with op://; you are not logged in, did not use the `op run` command, or the environment is setup incorrectly");
            } else {
                return token;
            }
        }
        return ghsaToken;
    }

    @CommandLine.Option(names = {
            "--ghsatoken"}, description = "API Key; it is highly recommend to set the environment variable, GITHUB_TOKEN, instead of using the command line option", interactive = true)
    public void setGhsaToken(String ghsaToken) {
        LOG.warn(
                "For easier use - consider setting an environment variable GITHUB_TOKEN.\n\nSee TODO for more information");
        this.ghsaToken = ghsaToken;
    }

    /**
     * Returns the NVD API Key if supplied.
     *
     * @return the NVD API Key if supplied; otherwise <code>null</code>
     */
    protected String getNvdKey() {
        if (nvdKey == null && System.getenv("NVD_API_KEY") != null) {
            String key = System.getenv("NVD_API_KEY");
            if (key != null && key.startsWith("op://")) {
                LOG.warn(
                        "NVD_API_KEY begins with op://; you are not logged in, did not use the `op run` command, or the environment is setup incorrectly");
            } else {
                return key;
            }
            return System.getenv("NVD_API_KEY");
        }
        return nvdKey;
    }

    @CommandLine.Option(names = {
            "--nvdkey"}, description = "NVD API Key; it is highly recommend to set the environment variable NVD_API_KEY instead of using the command line option", interactive = true)
    public void setNvdKey(String nvdKey) {
        LOG.warn(
                "For easier use - consider setting an environment variable NVD_API_KEY.\n\nSee TODO for more information");
        this.nvdKey = nvdKey;
    }

    @Override
    public Integer timedCall() throws Exception {
        if (isDebug()) {
            LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
            loggerContext.getLogger("io.github.jeremylong").setLevel(Level.DEBUG);
        }

        File loc = urlToFile(DatabaseCommand.class.getProtectionDomain().getCodeSource().getLocation().toString());
        File data = new File(loc.getParentFile(), "data");
        File vulnDb = new File(data, "vulnerabilities.db");
        String connectionString = "jdbc:sqlite:" + vulnDb.getAbsolutePath();
        if (!data.isDirectory() && !data.mkdirs()) {
            LOG.error("Unable to create data directory: " + data);
            return 1;
        }

        Configuration configuration = new Configuration();
        configuration.put(GHSA_TOKEN, getGhsaToken());
        configuration.put(NVD_API_KEY, getNvdKey());
        configuration.put(PROCESS_GHSA, Boolean.toString(!skipGHSA));
        configuration.put(PROCESS_NVD, Boolean.toString(!skipNVD));
        configuration.put(CONNECTION_STRING, connectionString);

        if (nvdCPEFilter != null && !nvdCPEFilter.isBlank()) {
            configuration.put(NVD_CPE_FILTER, nvdCPEFilter);
        }
        VulnerabilityService vulnerabilityService = new VulnerabilityService(configuration);
        vulnerabilityService.updateDatabase();
        return 0;
    }
}
