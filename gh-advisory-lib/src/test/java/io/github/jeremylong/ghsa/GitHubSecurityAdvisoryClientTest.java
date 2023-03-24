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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package io.github.jeremylong.ghsa;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

class GitHubSecurityAdvisoryClientTest {

    private static final Logger LOG = LoggerFactory.getLogger(GitHubSecurityAdvisoryClientTest.class);

    ZonedDateTime retrieveLastUpdated() {
        // TODO implement a storage/retrieval mechanism for the last updated date.

        return ZonedDateTime.now(ZoneOffset.UTC).minusDays(1);
    }

    void storeLastUpdated(ZonedDateTime lastUpdated) {
        // TODO implement a storage/retrieval mechanism for the last update time.
    }

    @Test
    void testNext() throws Exception {
        String apiKey = System.getenv("GITHUB_TOKEN");

        Assumptions.assumeTrue(apiKey != null, "env GITHUB_TOKEN not found - skipping test");
        Assumptions.assumeFalse(apiKey.startsWith("op:"),
                "env GITHUB_TOKEN found protected with 1password - skipping test");

        GitHubSecurityAdvisoryClientBuilder builder = GitHubSecurityAdvisoryClientBuilder
                .aGitHubSecurityAdvisoryClient().withApiKey(apiKey);

        ZonedDateTime lastUpdated = retrieveLastUpdated();
        if (lastUpdated != null) {
            builder.withUpdatedSinceFilter(lastUpdated);
        }
        try (GitHubSecurityAdvisoryClient client = builder.build()) {
            if (client.hasNext()) {
                Collection<SecurityAdvisory> items = client.next();
                // TODO do something useful with the SecurityAdvisories
                for (SecurityAdvisory i : items) {
                    LOG.info("Retrieved {}", i.getGhsaId());
                }
            }
            storeLastUpdated(client.getLastUpdated());
        }
    }
}