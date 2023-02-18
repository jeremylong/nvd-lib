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

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"lang", "value"})
public class LangString {

    /**
     * (Required)
     */
    @JsonProperty("lang")
    private String lang;
    /**
     * (Required)
     */
    @JsonProperty("value")
    private String value;

    /**
     * (Required)
     *
     * @return lang
     */
    @JsonProperty("lang")
    public String getLang() {
        return lang;
    }

    /**
     * (Required)
     *
     * @return value
     */
    @JsonProperty("value")
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "LangString{" + "lang='" + lang + '\'' + ", value='" + value + '\'' + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        LangString that = (LangString) o;
        return Objects.equals(lang, that.lang) && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lang, value);
    }
}
