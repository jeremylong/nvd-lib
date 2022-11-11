package dev.jeremylong.nvdlib;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RateMeterTest {

    @Test
    void check() throws InterruptedException {
        //ensure we can request up to the quantity in under the duration
        int durationLimit = 100;
        int queueSize = 2;
        RateMeter instance = new RateMeter(queueSize, durationLimit);
        long startTime = System.currentTimeMillis();
        instance.check();
        instance.check();
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        assertTrue(duration < durationLimit);

        //ensure requesting more than the quantity we are delayed
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