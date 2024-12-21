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
 * Copyright (c) 2022-2024 Jeremy Long. All Rights Reserved.
 */
package io.github.jeremylong.vulnz.cli.monitoring;

import io.github.jeremylong.vulnz.cli.commands.CveCommand;
import io.prometheus.metrics.expositionformats.OpenMetricsTextFormatWriter;
import io.prometheus.metrics.instrumentation.jvm.JvmMetrics;
import io.prometheus.metrics.model.registry.PrometheusRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Component
@ConditionalOnProperty(name = "metrics.enable", havingValue = "true")
public class PrometheusFileWriter {

    private static final Logger LOG = LoggerFactory.getLogger(PrometheusFileWriter.class);

    @Autowired
    private CveCommand command;

    @PostConstruct
    public void init() {
        JvmMetrics.builder().register();
    }

    @Scheduled(fixedRateString = "${metrics.write.interval:5000}")
    public void writeFile() {
        File directory = command.getCacheDirectory();
        if (directory != null) {
            final PrometheusRegistry defaultRegistry = PrometheusRegistry.defaultRegistry;
            try (FileOutputStream out = new FileOutputStream(new File(directory, "metrics"))) {
                OpenMetricsTextFormatWriter writer = new OpenMetricsTextFormatWriter(true, true);
                writer.write(out, defaultRegistry.scrape());
            } catch (IOException e) {
                LOG.error("Error writing metrics", e);
            }
        }
    }
}
