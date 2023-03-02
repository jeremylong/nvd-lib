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
package io.github.jeremylong.vulntools;

import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Iterator;

public interface PagedDataSource<T> extends AutoCloseable, Iterator<Collection<T>> {

    /**
     * Cleanup allocated resources.
     *
     * @throws Exception thrown if there is a problem.
     */
    @Override
    public void close() throws Exception;

    /**
     * Returns the last HTTP Status Code received.
     *
     * @return the last HTTP Status Code received.
     */
    public int getLastStatusCode();

    /**
     * Returns <code>true</code> if there are more records available; otherwise <code>false</code>.
     *
     * @return <code>true</code> if there are more records available; otherwise <code>false</code>.
     */
    @Override
    public boolean hasNext();

    /**
     * Returns the next collection of vulnerability data.
     *
     * @return a collection of vulnerability data.
     */
    @Override
    public Collection<T> next();

    /**
     * Returns the latest updated date.
     *
     * @return the latest updated date
     */
    public ZonedDateTime getLastUpdated();

}
