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

import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"id", "sourceIdentifier", "published", "lastModified", "vulnStatus", "evaluatorComment",
        "evaluatorSolution", "evaluatorImpact", "cisaExploitAdd", "cisaActionDue", "cisaRequiredAction",
        "cisaVulnerabilityName", "descriptions", "vendorComments", "metrics", "weaknesses", "configurations",
        "references"})
public class CveItem {

    @JsonProperty("id")
    private String id;
    @JsonProperty("sourceIdentifier")
    private String sourceIdentifier;
    @JsonProperty("vulnStatus")
    private String vulnStatus;
    @JsonProperty("published")
    @JsonFormat(pattern = "uuuu-MM-dd'T'HH:mm:ss.SSS", timezone = "UTC")
    private ZonedDateTime published;
    @JsonProperty("lastModified")
    @JsonFormat(pattern = "uuuu-MM-dd'T'HH:mm:ss.SSS", timezone = "UTC")
    private ZonedDateTime lastModified;
    @JsonProperty("evaluatorComment")
    private String evaluatorComment;
    @JsonProperty("evaluatorSolution")
    private String evaluatorSolution;
    @JsonProperty("evaluatorImpact")
    private String evaluatorImpact;
    @JsonProperty("cisaExploitAdd")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate cisaExploitAdd;
    @JsonProperty("cisaActionDue")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate cisaActionDue;
    @JsonProperty("cisaRequiredAction")
    private String cisaRequiredAction;
    @JsonProperty("cisaVulnerabilityName")
    private String cisaVulnerabilityName;
    /**
     * (Required)
     */
    @JsonProperty("descriptions")
    private List<LangString> descriptions;
    /**
     * (Required)
     */
    @JsonProperty("references")
    private List<Reference> references;
    /**
     * Metric scores for a vulnerability as found on NVD.
     */
    @JsonProperty("metrics")
    @JsonPropertyDescription("Metric scores for a vulnerability as found on NVD.")
    private Metrics metrics;
    @JsonProperty("weaknesses")
    private List<Weakness> weaknesses;
    @JsonProperty("configurations")
    private List<Config> configurations;
    @JsonProperty("vendorComments")
    private List<VendorComment> vendorComments;

    /**
     * @return id
     */
    @JsonProperty("id")
    public String getId() {
        return id;
    }

    /**
     * @return sourceIdentifier
     */
    @JsonProperty("sourceIdentifier")
    public String getSourceIdentifier() {
        return sourceIdentifier;
    }

    /**
     * @return vulnStatus
     */
    @JsonProperty("vulnStatus")
    public String getVulnStatus() {
        return vulnStatus;
    }

    /**
     * @return published
     */
    @JsonProperty("published")
    public ZonedDateTime getPublished() {
        return published;
    }

    /**
     * @return lastModified
     */
    @JsonProperty("lastModified")
    public ZonedDateTime getLastModified() {
        return lastModified;
    }

    /**
     * @return evaluatorComment
     */
    @JsonProperty("evaluatorComment")
    public String getEvaluatorComment() {
        return evaluatorComment;
    }

    /**
     * @return evaluatorSolution
     */
    @JsonProperty("evaluatorSolution")
    public String getEvaluatorSolution() {
        return evaluatorSolution;
    }

    /**
     * @return evaluatorImpact
     */
    @JsonProperty("evaluatorImpact")
    public String getEvaluatorImpact() {
        return evaluatorImpact;
    }

    /**
     * @return cisaExploitAdd
     */
    @JsonProperty("cisaExploitAdd")
    public LocalDate getCisaExploitAdd() {
        return cisaExploitAdd;
    }

    /**
     * @return cisaActionDue
     */
    @JsonProperty("cisaActionDue")
    public LocalDate getCisaActionDue() {
        return cisaActionDue;
    }

    /**
     * @return cisaRequiredAction
     */
    @JsonProperty("cisaRequiredAction")
    public String getCisaRequiredAction() {
        return cisaRequiredAction;
    }

    /**
     * @return cisaVulnerabilityName
     */
    @JsonProperty("cisaVulnerabilityName")
    public String getCisaVulnerabilityName() {
        return cisaVulnerabilityName;
    }

    /**
     * (Required)
     *
     * @return descriptions
     */
    @JsonProperty("descriptions")
    public List<LangString> getDescriptions() {
        return descriptions;
    }

    /**
     * (Required)
     *
     * @return references
     */
    @JsonProperty("references")
    public List<Reference> getReferences() {
        return references;
    }

    /**
     * Metric scores for a vulnerability as found on NVD.
     *
     * @return metrics
     */
    @JsonProperty("metrics")
    public Metrics getMetrics() {
        return metrics;
    }

    /**
     * @return weaknesses
     */
    @JsonProperty("weaknesses")
    public List<Weakness> getWeaknesses() {
        return weaknesses;
    }

    /**
     * @return configurations
     */
    @JsonProperty("configurations")
    public List<Config> getConfigurations() {
        return configurations;
    }

    /**
     * @return vendorComments
     */
    @JsonProperty("vendorComments")
    public List<VendorComment> getVendorComments() {
        return vendorComments;
    }

    @Override
    public String toString() {
        return "CveItem{" + "id='" + id + '\'' + ", sourceIdentifier='" + sourceIdentifier + '\'' + ", vulnStatus='"
                + vulnStatus + '\'' + ", published=" + published + ", lastModified=" + lastModified
                + ", evaluatorComment='" + evaluatorComment + '\'' + ", evaluatorSolution='" + evaluatorSolution + '\''
                + ", evaluatorImpact='" + evaluatorImpact + '\'' + ", cisaExploitAdd=" + cisaExploitAdd
                + ", cisaActionDue=" + cisaActionDue + ", cisaRequiredAction='" + cisaRequiredAction + '\''
                + ", cisaVulnerabilityName='" + cisaVulnerabilityName + '\'' + ", descriptions=" + descriptions
                + ", references=" + references + ", metrics=" + metrics + ", weaknesses=" + weaknesses
                + ", configurations=" + configurations + ", vendorComments=" + vendorComments + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CveItem cveItem = (CveItem) o;
        return Objects.equals(id, cveItem.id) && Objects.equals(sourceIdentifier, cveItem.sourceIdentifier)
                && Objects.equals(vulnStatus, cveItem.vulnStatus) && Objects.equals(published, cveItem.published)
                && Objects.equals(lastModified, cveItem.lastModified)
                && Objects.equals(evaluatorComment, cveItem.evaluatorComment)
                && Objects.equals(evaluatorSolution, cveItem.evaluatorSolution)
                && Objects.equals(evaluatorImpact, cveItem.evaluatorImpact)
                && Objects.equals(cisaExploitAdd, cveItem.cisaExploitAdd)
                && Objects.equals(cisaActionDue, cveItem.cisaActionDue)
                && Objects.equals(cisaRequiredAction, cveItem.cisaRequiredAction)
                && Objects.equals(cisaVulnerabilityName, cveItem.cisaVulnerabilityName)
                && Objects.equals(descriptions, cveItem.descriptions) && Objects.equals(references, cveItem.references)
                && Objects.equals(metrics, cveItem.metrics) && Objects.equals(weaknesses, cveItem.weaknesses)
                && Objects.equals(configurations, cveItem.configurations)
                && Objects.equals(vendorComments, cveItem.vendorComments);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, sourceIdentifier, vulnStatus, published, lastModified, evaluatorComment,
                evaluatorSolution, evaluatorImpact, cisaExploitAdd, cisaActionDue, cisaRequiredAction,
                cisaVulnerabilityName, descriptions, references, metrics, weaknesses, configurations, vendorComments);
    }
}
