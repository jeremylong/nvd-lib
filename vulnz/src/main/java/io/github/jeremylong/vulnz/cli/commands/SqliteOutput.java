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

import io.github.jeremylong.vulnz.cli.model.BasicOutput;
import io.github.jeremylong.nvdlib.NvdCveApi;
import io.github.jeremylong.nvdlib.NvdCveApiBuilder;
import io.github.jeremylong.nvdlib.nvd.DefCveItem;
import io.github.jeremylong.nvdlib.nvd.Config;
import io.github.jeremylong.nvdlib.nvd.CpeMatch;
import io.github.jeremylong.nvdlib.nvd.Node;

abstract class SqliteOutput<T> extends Output<T> {
    private Connection connection = null;
    private Statement statement = null;
    private PreparedStatement insert = null;

    protected SqliteOutput(String file, String create, String insert) throws Exception {
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:" + file);
            statement = connection.createStatement();
            statement.executeUpdate(create);
            this.insert = connection.prepareStatement(insert);
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    protected abstract void populateColumns(PreparedStatement insert, T item) throws Exception;

    @Override
    protected void writeOne(T t) throws Exception {
        populateColumns(insert, t);
        insert.executeUpdate();
    }

    @Override
    protected void close() throws Exception {
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

    protected String writeJson(Object object) throws Exception {
        StringWriter stringWriter = new StringWriter();
        objectMapper.writeValue(stringWriter, object);
        return stringWriter.toString();
    }
}
