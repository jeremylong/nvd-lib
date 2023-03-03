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
package io.github.jeremylong.vulnz.cli.commands;

import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Iterator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.github.jeremylong.vulntools.PagedDataSource;
import io.github.jeremylong.vulnz.cli.model.BasicOutput;

abstract class Output<T> {

    protected final ObjectMapper objectMapper;

    protected Output() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public BasicOutput write(PagedDataSource<T> api) throws Exception {
        BasicOutput output = new BasicOutput();

        try {
            while (api.hasNext()) {
                Collection<T> list = api.next();
                if (list != null) {
                    output.setSuccess(true);
                    output.addCount(list.size());
                    for (T c : list) {
                        writeOne(c);
                    }
                    if (output.getLastModifiedDate() == null
                            || output.getLastModifiedDate().isBefore(api.getLastUpdated())) {
                        output.setLastModifiedDate(api.getLastUpdated());
                    }
                } else {
                    output.setSuccess(false);
                    throw new IllegalStateException("list should not be null");
                }
            }
        }
        finally {
            close();
        }
        return output;
    }

    abstract protected void writeOne(T t) throws Exception;

    protected void close() throws Exception {
    }

}