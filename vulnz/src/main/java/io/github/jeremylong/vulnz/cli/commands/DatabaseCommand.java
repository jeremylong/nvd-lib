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
import io.github.jeremylong.openvulnerability.VulnerabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

import static com.diogonunes.jcolor.Ansi.colorize;

@Component
@CommandLine.Command(name = "database", description = "Builds a vulnerability database from freely available data sources")
public class DatabaseCommand extends AbstractJsonCommand {
    /**
     * Reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(DatabaseCommand.class);

    @CommandLine.Option(names = {"--endpoint"}, description = "The GraphQL endpoint of GH or GHE")
    private boolean endpoint;
    // yes - these should not be a string, but seriously down the call path the HttpClient
    // doesn't support passing a header in as a char[]...
    private String ghsaToken = null;
    private String nvdKey = null;

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
        jakarta.activation.DataSource ds;
        VulnerabilityService vulnerabilityService = new VulnerabilityService();
        vulnerabilityService.updateDatabase(getGhsaToken(), getNvdKey());
        return 0;
    }
}
