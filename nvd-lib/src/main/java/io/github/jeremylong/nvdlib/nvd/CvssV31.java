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
package io.github.jeremylong.nvdlib.nvd;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"source", "type", "cvssData", "exploitabilityScore", "impactScore"})
public class CvssV31 {

    /**
     * (Required)
     */
    @JsonProperty("source")
    private String source;
    /**
     * (Required)
     */
    @JsonProperty("type")
    private Type type;
    /**
     * JSON Schema for Common Vulnerability Scoring System version 3.1
     *
     * (Required)
     */
    @JsonProperty("cvssData")
    private CvssV31Data cvssData;
    /**
     * CVSS subscore.
     */
    @JsonProperty("exploitabilityScore")
    @JsonPropertyDescription("CVSS subscore.")
    private Double exploitabilityScore;
    /**
     * CVSS subscore.
     */
    @JsonProperty("impactScore")
    @JsonPropertyDescription("CVSS subscore.")
    private Double impactScore;

    /**
     * (Required)
     *
     * @return source
     */
    @JsonProperty("source")
    public String getSource() {
        return source;
    }

    /**
     * (Required)
     *
     * @return type
     */
    @JsonProperty("type")
    public Type getType() {
        return type;
    }

    /**
     * JSON Schema for Common Vulnerability Scoring System version 3.1
     *
     * (Required)
     *
     * @return cvssData
     */
    @JsonProperty("cvssData")
    public CvssV31Data getCvssData() {
        return cvssData;
    }

    /**
     * CVSS subscore.
     *
     * @return exploitabilityScore
     */
    @JsonProperty("exploitabilityScore")
    public Double getExploitabilityScore() {
        return exploitabilityScore;
    }

    /**
     * CVSS subscore.
     *
     * @return impactScore
     */
    @JsonProperty("impactScore")
    public Double getImpactScore() {
        return impactScore;
    }

    @Override
    public String toString() {
        return "CvssV31{" + "source='" + source + '\'' + ", type=" + type + ", cvssData=" + cvssData
                + ", exploitabilityScore=" + exploitabilityScore + ", impactScore=" + impactScore + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CvssV31 cvssV31 = (CvssV31) o;
        return Objects.equals(source, cvssV31.source) && type == cvssV31.type
                && Objects.equals(cvssData, cvssV31.cvssData)
                && Objects.equals(exploitabilityScore, cvssV31.exploitabilityScore)
                && Objects.equals(impactScore, cvssV31.impactScore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(source, type, cvssData, exploitabilityScore, impactScore);
    }

    public enum Type {

        PRIMARY("Primary"), SECONDARY("Secondary");

        private final static Map<String, Type> CONSTANTS = new HashMap<>();

        static {
            for (Type c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        Type(String value) {
            this.value = value;
        }

        @JsonCreator
        public static Type fromValue(String value) {
            Type constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

    }

}
