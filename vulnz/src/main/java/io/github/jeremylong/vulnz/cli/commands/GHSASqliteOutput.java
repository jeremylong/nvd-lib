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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;

import io.github.jeremylong.vulnz.cli.model.BasicOutput;
import io.github.jeremylong.ghsa.SecurityAdvisory;
import io.github.jeremylong.ghsa.Identifier;

class GHSASqliteOutput extends SqliteOutput<SecurityAdvisory> {
    protected GHSASqliteOutput() {
        this("ghsa");
    }

    private GHSASqliteOutput(String tableName) {
        super(tableName,
                "create table if not exists " + tableName + " (id name, identifiers text, raw json, primary key(id))",
                "insert or replace into " + tableName + " values (?, ?, ?)");
    }

    @Override
    protected void populateColumns(PreparedStatement insert, SecurityAdvisory advisory) throws Exception {
        insert.setString(1, advisory.getGhsaId());
        String identifiers = null;
        for (Identifier identifier : advisory.getIdentifiers()) {
            if (identifiers == null) {
                identifiers = "\"" + identifier.getValue() + "\"";
            } else {
                identifiers += ", \"" + identifier.getValue() + "\"";
            }
        }
        insert.setString(2, "[" + identifiers + "]");
        insert.setString(3, writeJson(advisory));
    }
}
