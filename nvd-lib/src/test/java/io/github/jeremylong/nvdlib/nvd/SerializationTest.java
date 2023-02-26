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
package io.github.jeremylong.nvdlib.nvd;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerializationTest {

    @Test
    void thereAndBackAgain() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        String json;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("nvd.json"), StandardCharsets.UTF_8))) {
            json = r.lines().collect(Collectors.joining("\n"));
        }
        CveApiJson20 current = objectMapper.readValue(json, CveApiJson20.class);
        assertEquals(2000, current.getVulnerabilities().size());

        String serialized = objectMapper.writeValueAsString(current);
        CveApiJson20 hydrated = objectMapper.readValue(serialized, CveApiJson20.class);
        String reserialized = objectMapper.writeValueAsString(hydrated);
        assertTrue(serialized.equals(reserialized));
    }
}