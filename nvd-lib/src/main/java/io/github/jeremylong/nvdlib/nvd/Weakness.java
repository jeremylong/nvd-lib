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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"source", "type", "description"})
public class Weakness {

    /**
     * (Required)
     */
    @JsonProperty("source")
    private String source;
    /**
     * (Required)
     */
    @JsonProperty("type")
    private String type;
    /**
     * (Required)
     */
    @JsonProperty("description")
    private List<LangString> description;// = new ArrayList<>();

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
    public String getType() {
        return type;
    }

    /**
     * (Required)
     *
     * @return description
     */
    @JsonProperty("description")
    public List<LangString> getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return "Weakness{" + "source='" + source + '\'' + ", type='" + type + '\'' + ", description=" + description
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        Weakness weakness = (Weakness) o;
        return Objects.equals(source, weakness.source) && Objects.equals(type, weakness.type)
                && Objects.equals(description, weakness.description);
    }

    @Override
    public int hashCode() {
        return Objects.hash(source, type, description);
    }
}
