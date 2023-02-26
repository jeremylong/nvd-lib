/*
 *  Copyright 2023 Jeremy Long
 *
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
 */
package io.github.jeremylong.nvdlib.nvd;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * JSON Schema for NVD Vulnerability Data API version 2.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"resultsPerPage", "startIndex", "totalResults", "format", "version", "timestamp",
        "vulnerabilities"})
public class CveApiJson20 {

    /**
     * (Required)
     */
    @JsonProperty("resultsPerPage")
    private Integer resultsPerPage;
    /**
     * (Required)
     */
    @JsonProperty("startIndex")
    private Integer startIndex;
    /**
     * (Required)
     */
    @JsonProperty("totalResults")
    private Integer totalResults;
    /**
     * (Required)
     */
    @JsonProperty("format")
    private String format;
    /**
     * (Required)
     */
    @JsonProperty("version")
    private String version;
    /**
     * (Required)
     */
    @JsonProperty("timestamp")
    @JsonFormat(pattern = "uuuu-MM-dd'T'HH:mm:ss.SSS", timezone = "UTC")
    private ZonedDateTime timestamp;
    /**
     * NVD feed array of CVE (Required)
     */
    @JsonProperty("vulnerabilities")
    @JsonPropertyDescription("NVD feed array of CVE")
    private List<DefCveItem> vulnerabilities;// = new ArrayList<>();

    /**
     * (Required)
     *
     * @return resultsPerPage
     */
    @JsonProperty("resultsPerPage")
    public Integer getResultsPerPage() {
        return resultsPerPage;
    }

    /**
     * (Required)
     *
     * @return startIndex
     */
    @JsonProperty("startIndex")
    public Integer getStartIndex() {
        return startIndex;
    }

    /**
     * (Required)
     *
     * @return totalResults
     */
    @JsonProperty("totalResults")
    public Integer getTotalResults() {
        return totalResults;
    }

    /**
     * (Required)
     *
     * @return format
     */
    @JsonProperty("format")
    public String getFormat() {
        return format;
    }

    /**
     * (Required)
     *
     * @return version
     */
    @JsonProperty("version")
    public String getVersion() {
        return version;
    }

    /**
     * (Required)
     *
     * @return timestamp
     */
    @JsonProperty("timestamp")
    public ZonedDateTime getTimestamp() {
        return timestamp;
    }

    /**
     * NVD feed array of CVE (Required)
     *
     * @return vulnerabilities
     */
    @JsonProperty("vulnerabilities")
    public List<DefCveItem> getVulnerabilities() {
        return vulnerabilities;
    }

    @Override
    public String toString() {
        return "CveApiJson20{" + "resultsPerPage=" + resultsPerPage + ", startIndex=" + startIndex + ", totalResults="
                + totalResults + ", format='" + format + '\'' + ", version='" + version + '\'' + ", timestamp="
                + timestamp + ", vulnerabilities=" + vulnerabilities + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CveApiJson20 that = (CveApiJson20) o;
        return Objects.equals(resultsPerPage, that.resultsPerPage) && Objects.equals(startIndex, that.startIndex)
                && Objects.equals(totalResults, that.totalResults) && Objects.equals(format, that.format)
                && Objects.equals(version, that.version) && Objects.equals(timestamp, that.timestamp)
                && Objects.equals(vulnerabilities, that.vulnerabilities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resultsPerPage, startIndex, totalResults, format, version, timestamp, vulnerabilities);
    }
}
