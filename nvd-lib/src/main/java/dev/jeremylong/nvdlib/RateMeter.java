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

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

public class RateMeter {
    private BlockingQueue<Ticket> queue = new DelayQueue<>();
    private int quantity;
    private long durationMilliseconds;

    public RateMeter(int quantity, long durationMilliseconds) {
        this.quantity = quantity;
        this.durationMilliseconds = durationMilliseconds;
    }

    public synchronized void check() throws InterruptedException {
        if (queue.size() < quantity) {
            queue.put(new Ticket(durationMilliseconds));
        } else {
            queue.take();
        }
    }

    class Ticket implements Delayed {

        private long startTime;

        Ticket(long delayInMilliseconds) {
            this.startTime = System.currentTimeMillis() + delayInMilliseconds;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            long diff = startTime - System.currentTimeMillis();
            return unit.convert(diff, TimeUnit.MILLISECONDS);
        }

        @Override
        public int compareTo(Delayed o) {
            return (int) (this.startTime - ((Ticket) o).startTime);
        }
    }
}
