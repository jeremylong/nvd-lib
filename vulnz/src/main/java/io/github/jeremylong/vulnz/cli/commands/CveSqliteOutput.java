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

import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.github.jeremylong.vulnz.cli.model.BasicOutput;
import io.github.jeremylong.nvdlib.NvdCveApi;
import io.github.jeremylong.nvdlib.NvdCveApiBuilder;
import io.github.jeremylong.nvdlib.nvd.DefCveItem;
import io.github.jeremylong.nvdlib.nvd.CveItem;
import io.github.jeremylong.nvdlib.nvd.Config;
import io.github.jeremylong.nvdlib.nvd.CpeMatch;
import io.github.jeremylong.nvdlib.nvd.Node;

class CveSqliteOutput extends SqliteOutput<DefCveItem> {
    protected CveSqliteOutput() {
        super("cve",
                "create table if not exists cve (id name, sourceIdentifier text, cpes text, raw text, primary key(id))",
                "insert or replace into cve values (?, ?, ?, ?)");
    }

    @Override
    protected void populateColumns(PreparedStatement insert, DefCveItem defCve) throws Exception {
        CveItem cve = defCve.getCve();
        insert.setString(1, cve.getId());
        insert.setString(2, cve.getSourceIdentifier());
        String cpes = null;
        if (cve.getConfigurations() != null) {
            for (Config config : cve.getConfigurations()) {
                for (Node node : config.getNodes()) {
                    for (CpeMatch match : node.getCpeMatch()) {
                        if (cpes == null) {
                            cpes = "\"" + match.getCriteria() + "\"";
                        } else {
                            cpes += ", \"" + match.getCriteria() + "\"";
                        }
                    }
                }
            }
        }
        insert.setString(3, "[" + cpes + "]");
        insert.setString(4, writeJson(cve));
    }

    private String writeJson(CveItem cve) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        StringWriter stringWriter = new StringWriter();
        objectMapper.writeValue(stringWriter, cve);
        return stringWriter.toString();
    }
}
