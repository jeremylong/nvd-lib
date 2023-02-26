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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Future response.
 */
class SimpleFutureResponse implements FutureCallback<SimpleHttpResponse> {
    /**
     * Reference to the logger.
     */
    private final Logger log = LoggerFactory.getLogger(SimpleFutureResponse.class);

    @Override
    public void completed(SimpleHttpResponse result) {
        // String response = result.getBodyText();
        // log.debug("response::{}", response);
    }

    @Override
    public void failed(Exception ex) {
        log.debug("request failed", ex);
    }

    @Override
    public void cancelled() {
        // do nothing
    }
}
