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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.Objects;

/**
 * An individual package.
 * 
 * <pre>
 * type SecurityAdvisoryPackage
 * </pre>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder({"ecosystem", "name"})
public class Package {

    @JsonProperty("ecosystem")
    private String ecosystem;

    @JsonProperty("name")
    private String name;

    /**
     * The ecosystem the package belongs to, e.g. RUBYGEMS, NPM.
     *
     * @return The ecosystem the package belongs.
     */
    public String getEcosystem() {
        return ecosystem;
    }

    /**
     * The package name.
     *
     * @return the package name.
     */
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "Package{" + "ecosystem='" + ecosystem + '\'' + ", name='" + name + '\'' + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        Package aPackage = (Package) o;
        return Objects.equals(ecosystem, aPackage.ecosystem) && Objects.equals(name, aPackage.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ecosystem, name);
    }
}
