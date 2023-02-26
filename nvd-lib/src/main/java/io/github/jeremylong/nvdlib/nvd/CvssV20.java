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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * JSON Schema for Common Vulnerability Scoring System version 2.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"version", "vectorString", "accessVector", "accessComplexity", "authentication",
        "confidentialityImpact", "integrityImpact", "availabilityImpact", "baseScore", "exploitability",
        "remediationLevel", "reportConfidence", "temporalScore", "collateralDamagePotential", "targetDistribution",
        "confidentialityRequirement", "integrityRequirement", "availabilityRequirement", "environmentalScore"})
public class CvssV20 {

    /**
     * CVSS Version (Required)
     */
    @JsonProperty("version")
    @JsonPropertyDescription("CVSS Version")
    private Version version;
    /**
     * (Required)
     */
    @JsonProperty("vectorString")
    private String vectorString;
    @JsonProperty("accessVector")
    private AccessVectorType accessVector;
    @JsonProperty("accessComplexity")
    private AccessComplexityType accessComplexity;
    @JsonProperty("authentication")
    private AuthenticationType authentication;
    @JsonProperty("confidentialityImpact")
    private CiaType confidentialityImpact;
    @JsonProperty("integrityImpact")
    private CiaType integrityImpact;
    @JsonProperty("availabilityImpact")
    private CiaType availabilityImpact;
    /**
     * (Required)
     */
    @JsonProperty("baseScore")
    private Double baseScore;
    @JsonProperty("exploitability")
    private ExploitabilityType exploitability;
    @JsonProperty("remediationLevel")
    private RemediationLevelType remediationLevel;
    @JsonProperty("reportConfidence")
    private ReportConfidenceType reportConfidence;
    @JsonProperty("temporalScore")
    private Double temporalScore;
    @JsonProperty("collateralDamagePotential")
    private CollateralDamagePotentialType collateralDamagePotential;
    @JsonProperty("targetDistribution")
    private TargetDistributionType targetDistribution;
    @JsonProperty("confidentialityRequirement")
    private CiaRequirementType confidentialityRequirement;
    @JsonProperty("integrityRequirement")
    private CiaRequirementType integrityRequirement;
    @JsonProperty("availabilityRequirement")
    private CiaRequirementType availabilityRequirement;
    @JsonProperty("environmentalScore")
    private Double environmentalScore;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new LinkedHashMap<>();

    /**
     * CVSS Version (Required)
     *
     * @return version
     */
    @JsonProperty("version")
    public Version getVersion() {
        return version;
    }

    /**
     * (Required)
     *
     * @return vectorString
     */
    @JsonProperty("vectorString")
    public String getVectorString() {
        return vectorString;
    }

    /**
     * @return accessVector
     */
    @JsonProperty("accessVector")
    public AccessVectorType getAccessVector() {
        return accessVector;
    }

    /**
     * @return accessComplexity
     */
    @JsonProperty("accessComplexity")
    public AccessComplexityType getAccessComplexity() {
        return accessComplexity;
    }

    /**
     * @return authentication
     */
    @JsonProperty("authentication")
    public AuthenticationType getAuthentication() {
        return authentication;
    }

    /**
     * @return confidentialityImpact
     */
    @JsonProperty("confidentialityImpact")
    public CiaType getConfidentialityImpact() {
        return confidentialityImpact;
    }

    /**
     * @return integrityImpact
     */
    @JsonProperty("integrityImpact")
    public CiaType getIntegrityImpact() {
        return integrityImpact;
    }

    /**
     * @return availabilityImpact
     */
    @JsonProperty("availabilityImpact")
    public CiaType getAvailabilityImpact() {
        return availabilityImpact;
    }

    /**
     * (Required)
     *
     * @return baseScore
     */
    @JsonProperty("baseScore")
    public Double getBaseScore() {
        return baseScore;
    }

    /**
     * @return exploitability
     */
    @JsonProperty("exploitability")
    public ExploitabilityType getExploitability() {
        return exploitability;
    }

    /**
     * @return remediationLevel
     */
    @JsonProperty("remediationLevel")
    public RemediationLevelType getRemediationLevel() {
        return remediationLevel;
    }

    /**
     * @return reportConfidence
     */
    @JsonProperty("reportConfidence")
    public ReportConfidenceType getReportConfidence() {
        return reportConfidence;
    }

    /**
     * @return temporalScore
     */
    @JsonProperty("temporalScore")
    public Double getTemporalScore() {
        return temporalScore;
    }

    /**
     * @return collateralDamagePotential
     */
    @JsonProperty("collateralDamagePotential")
    public CollateralDamagePotentialType getCollateralDamagePotential() {
        return collateralDamagePotential;
    }

    /**
     * @return targetDistribution
     */
    @JsonProperty("targetDistribution")
    public TargetDistributionType getTargetDistribution() {
        return targetDistribution;
    }

    /**
     * @return confidentialityRequirement
     */
    @JsonProperty("confidentialityRequirement")
    public CiaRequirementType getConfidentialityRequirement() {
        return confidentialityRequirement;
    }

    /**
     * @return integrityRequirement
     */
    @JsonProperty("integrityRequirement")
    public CiaRequirementType getIntegrityRequirement() {
        return integrityRequirement;
    }

    /**
     * @return availabilityRequirement
     */
    @JsonProperty("availabilityRequirement")
    public CiaRequirementType getAvailabilityRequirement() {
        return availabilityRequirement;
    }

    /**
     * @return environmentalScore
     */
    @JsonProperty("environmentalScore")
    public Double getEnvironmentalScore() {
        return environmentalScore;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        return "CvssV20{" + "version=" + version + ", vectorString='" + vectorString + '\'' + ", accessVector="
                + accessVector + ", accessComplexity=" + accessComplexity + ", authentication=" + authentication
                + ", confidentialityImpact=" + confidentialityImpact + ", integrityImpact=" + integrityImpact
                + ", availabilityImpact=" + availabilityImpact + ", baseScore=" + baseScore + ", exploitability="
                + exploitability + ", remediationLevel=" + remediationLevel + ", reportConfidence=" + reportConfidence
                + ", temporalScore=" + temporalScore + ", collateralDamagePotential=" + collateralDamagePotential
                + ", targetDistribution=" + targetDistribution + ", confidentialityRequirement="
                + confidentialityRequirement + ", integrityRequirement=" + integrityRequirement
                + ", availabilityRequirement=" + availabilityRequirement + ", environmentalScore=" + environmentalScore
                + ", additionalProperties=" + additionalProperties + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CvssV20 cvssV20 = (CvssV20) o;
        return version == cvssV20.version && Objects.equals(vectorString, cvssV20.vectorString)
                && accessVector == cvssV20.accessVector && accessComplexity == cvssV20.accessComplexity
                && authentication == cvssV20.authentication && confidentialityImpact == cvssV20.confidentialityImpact
                && integrityImpact == cvssV20.integrityImpact && availabilityImpact == cvssV20.availabilityImpact
                && Objects.equals(baseScore, cvssV20.baseScore) && exploitability == cvssV20.exploitability
                && remediationLevel == cvssV20.remediationLevel && reportConfidence == cvssV20.reportConfidence
                && Objects.equals(temporalScore, cvssV20.temporalScore)
                && collateralDamagePotential == cvssV20.collateralDamagePotential
                && targetDistribution == cvssV20.targetDistribution
                && confidentialityRequirement == cvssV20.confidentialityRequirement
                && integrityRequirement == cvssV20.integrityRequirement
                && availabilityRequirement == cvssV20.availabilityRequirement
                && Objects.equals(environmentalScore, cvssV20.environmentalScore)
                && Objects.equals(additionalProperties, cvssV20.additionalProperties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, vectorString, accessVector, accessComplexity, authentication,
                confidentialityImpact, integrityImpact, availabilityImpact, baseScore, exploitability, remediationLevel,
                reportConfidence, temporalScore, collateralDamagePotential, targetDistribution,
                confidentialityRequirement, integrityRequirement, availabilityRequirement, environmentalScore,
                additionalProperties);
    }

    public enum AccessComplexityType {

        HIGH("HIGH"), MEDIUM("MEDIUM"), LOW("LOW");

        private final static Map<String, AccessComplexityType> CONSTANTS = new HashMap<>();

        static {
            for (AccessComplexityType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        AccessComplexityType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static AccessComplexityType fromValue(String value) {
            AccessComplexityType constant = CONSTANTS.get(value);
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

    public enum AccessVectorType {

        NETWORK("NETWORK"), ADJACENT_NETWORK("ADJACENT_NETWORK"), LOCAL("LOCAL");

        private final static Map<String, AccessVectorType> CONSTANTS = new HashMap<>();

        static {
            for (AccessVectorType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        AccessVectorType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static AccessVectorType fromValue(String value) {
            AccessVectorType constant = CONSTANTS.get(value);
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

    public enum AuthenticationType {

        MULTIPLE("MULTIPLE"), SINGLE("SINGLE"), NONE("NONE");

        private final static Map<String, AuthenticationType> CONSTANTS = new HashMap<>();

        static {
            for (AuthenticationType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        AuthenticationType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static AuthenticationType fromValue(String value) {
            AuthenticationType constant = CONSTANTS.get(value);
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

    public enum CiaRequirementType {

        LOW("LOW"), MEDIUM("MEDIUM"), HIGH("HIGH"), NOT_DEFINED("NOT_DEFINED");

        private final static Map<String, CiaRequirementType> CONSTANTS = new HashMap<>();

        static {
            for (CiaRequirementType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        CiaRequirementType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static CiaRequirementType fromValue(String value) {
            CiaRequirementType constant = CONSTANTS.get(value);
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

    public enum CiaType {

        NONE("NONE"), PARTIAL("PARTIAL"), COMPLETE("COMPLETE");

        private final static Map<String, CiaType> CONSTANTS = new HashMap<>();

        static {
            for (CiaType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        CiaType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static CiaType fromValue(String value) {
            CiaType constant = CONSTANTS.get(value);
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

    public enum CollateralDamagePotentialType {

        NONE("NONE"), LOW("LOW"), LOW_MEDIUM("LOW_MEDIUM"), MEDIUM_HIGH("MEDIUM_HIGH"), HIGH("HIGH"), NOT_DEFINED(
                "NOT_DEFINED");

        private final static Map<String, CollateralDamagePotentialType> CONSTANTS = new HashMap<>();

        static {
            for (CollateralDamagePotentialType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        CollateralDamagePotentialType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static CollateralDamagePotentialType fromValue(String value) {
            CollateralDamagePotentialType constant = CONSTANTS.get(value);
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

    public enum ExploitabilityType {

        UNPROVEN("UNPROVEN"), PROOF_OF_CONCEPT("PROOF_OF_CONCEPT"), FUNCTIONAL("FUNCTIONAL"), HIGH("HIGH"), NOT_DEFINED(
                "NOT_DEFINED");

        private final static Map<String, ExploitabilityType> CONSTANTS = new HashMap<>();

        static {
            for (ExploitabilityType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        ExploitabilityType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static ExploitabilityType fromValue(String value) {
            ExploitabilityType constant = CONSTANTS.get(value);
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

    public enum RemediationLevelType {

        OFFICIAL_FIX("OFFICIAL_FIX"), TEMPORARY_FIX("TEMPORARY_FIX"), WORKAROUND("WORKAROUND"), UNAVAILABLE(
                "UNAVAILABLE"), NOT_DEFINED("NOT_DEFINED");

        private final static Map<String, RemediationLevelType> CONSTANTS = new HashMap<>();

        static {
            for (RemediationLevelType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        RemediationLevelType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static RemediationLevelType fromValue(String value) {
            RemediationLevelType constant = CONSTANTS.get(value);
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

    public enum ReportConfidenceType {

        UNCONFIRMED("UNCONFIRMED"), UNCORROBORATED("UNCORROBORATED"), CONFIRMED("CONFIRMED"), NOT_DEFINED(
                "NOT_DEFINED");

        private final static Map<String, ReportConfidenceType> CONSTANTS = new HashMap<>();

        static {
            for (ReportConfidenceType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        ReportConfidenceType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static ReportConfidenceType fromValue(String value) {
            ReportConfidenceType constant = CONSTANTS.get(value);
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

    public enum TargetDistributionType {

        NONE("NONE"), LOW("LOW"), MEDIUM("MEDIUM"), HIGH("HIGH"), NOT_DEFINED("NOT_DEFINED");

        private final static Map<String, TargetDistributionType> CONSTANTS = new HashMap<>();

        static {
            for (TargetDistributionType c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        TargetDistributionType(String value) {
            this.value = value;
        }

        @JsonCreator
        public static TargetDistributionType fromValue(String value) {
            TargetDistributionType constant = CONSTANTS.get(value);
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

    /**
     * CVSS Version
     */
    public enum Version {

        _2_0("2.0");

        private final static Map<String, Version> CONSTANTS = new HashMap<>();

        static {
            for (Version c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        Version(String value) {
            this.value = value;
        }

        @JsonCreator
        public static Version fromValue(String value) {
            Version constant = CONSTANTS.get(value);
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
