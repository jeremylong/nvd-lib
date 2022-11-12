/*
 *  Copyright 2022 Jeremy Long
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
package dev.jeremylong.nvdlib;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RateMeterTest {

    @Test
    void check() throws InterruptedException {
        // ensure we can request up to the quantity in under the duration
        int durationLimit = 100;
        int queueSize = 2;
        RateMeter instance = new RateMeter(queueSize, durationLimit);
        long startTime = System.currentTimeMillis();
        instance.check();
        instance.check();
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        assertTrue(duration < durationLimit);

        // ensure requesting more than the quantity we are delayed
        instance = new RateMeter(queueSize, durationLimit);
        startTime = System.currentTimeMillis();
        instance.check();
        instance.check();
        instance.check();
        endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        assertTrue(duration > durationLimit);
    }
}