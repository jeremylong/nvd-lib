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
package io.github.jeremylong.nvdlib;

import io.github.jeremylong.nvdlib.nvd.DefCveItem;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collection;

class NvdCveApiTest {

    private static final Logger LOG = LoggerFactory.getLogger(NvdCveApiTest.class);

    ZonedDateTime retrieveLastUpdated() {
        // TODO implement a storage/retrieval mechanism.
        return ZonedDateTime.now(ZoneOffset.UTC).minusDays(5);
    }

    void storeLasUpdated(ZonedDateTime lastUpdated) {
        // TODO implement a storage/retrieval mechanism.
    }

    @Test
    public void update() {
        String apiKey = System.getenv("NVD_API_KEY");
        Assumptions.assumeFalse(apiKey.startsWith("op:"),
                "env NVD_API_KEY found protected with 1password - skipping test");

        ZonedDateTime lastModifiedRequest = retrieveLastUpdated();
        NvdCveApiBuilder builder = NvdCveApiBuilder.aNvdCveApi();
        if (lastModifiedRequest != null) {
            ZonedDateTime end = lastModifiedRequest.minusDays(-120);
            builder.withLastModifiedFilter(lastModifiedRequest, end);
        }
        // TODO add any additional filters via the builder's `withfilter()`

        // TODO add API key with builder's `withApiKey()`

        try (NvdCveApi api = builder.build()) {
            // in a real world case - `while` would be used instead of `if`
            if (api.hasNext()) {
                Collection<DefCveItem> items = api.next();
                // TODO do something with the items
                for (DefCveItem i : items) {
                    LOG.info("Retrieved {}", i.getCve().getId());
                }
            }
            lastModifiedRequest = api.getLastUpdated();
        } catch (Exception e) {
            e.printStackTrace();
        }
        storeLasUpdated(lastModifiedRequest);
    }
}