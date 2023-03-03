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
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Iterator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.github.jeremylong.vulntools.PagedDataSource;
import io.github.jeremylong.vulnz.cli.model.BasicOutput;
import io.github.jeremylong.nvdlib.NvdCveApi;
import io.github.jeremylong.nvdlib.NvdCveApiBuilder;
import io.github.jeremylong.nvdlib.nvd.DefCveItem;
import io.github.jeremylong.nvdlib.nvd.Config;
import io.github.jeremylong.nvdlib.nvd.CpeMatch;
import io.github.jeremylong.nvdlib.nvd.Node;

abstract class SqliteOutput<T> {
    private final ObjectMapper objectMapper;
    private final String tableName;
    private final String create;
    private final String insert;

    protected SqliteOutput(String tableName, String create, String insert) {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        this.tableName = tableName;
        this.create = create;
        this.insert = insert;
    }

    public static CveSqliteOutput csv() {
        return new CveSqliteOutput();
    }

    public static GHSASqliteOutput ghsa() {
        return new GHSASqliteOutput();
    }

    protected abstract void populateColumns(PreparedStatement insert, T item) throws Exception;

    public BasicOutput writeToDb(PagedDataSource<T> api, String file) throws Exception {
        BasicOutput output = new BasicOutput();

        // would be better to just use try-with-resources here, but spotbugs doesn't let
        // us... https://github.com/spotbugs/spotbugs/issues/1338
        Connection connection = null;
        Statement statement = null;
        PreparedStatement insert = null;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:" + file);
            statement = connection.createStatement();
            statement.executeUpdate(create);
            insert = connection.prepareStatement(SqliteOutput.this.insert);

            while (api.hasNext()) {
                Collection<T> list = api.next();
                if (list != null) {
                    output.setSuccess(true);
                    output.addCount(list.size());
                    for (T c : list) {
                        populateColumns(insert, c);
                        insert.executeUpdate();
                    }
                    if (output.getLastModifiedDate() == null
                            || output.getLastModifiedDate().isBefore(api.getLastUpdated())) {
                        output.setLastModifiedDate(api.getLastUpdated());
                    }
                } else {
                    output.setSuccess(false);
                    output.setReason(String.format("Received HTTP Status Code: %s", api.getLastStatusCode()));
                }
            }
        }
        finally {
            try {
                try {
                    if (statement != null) {
                        statement.close();
                    }
                }
                finally {
                    if (insert != null) {
                        insert.close();
                    }
                }
            }
            finally {
                if (connection != null) {
                    connection.close();
                }
            }
        }

        return output;
    }

    protected String writeJson(Object object) throws Exception {
        StringWriter stringWriter = new StringWriter();
        objectMapper.writeValue(stringWriter, object);
        return stringWriter.toString();
    }
}
