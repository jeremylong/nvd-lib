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
 * Copyright (c) 2022-2025 Jeremy Long. All Rights Reserved.
 */
package io.github.jeremylong.vulnz.cli;

import io.github.jeremylong.vulnz.cli.commands.MainCommand;
import io.prometheus.metrics.core.metrics.Counter;
import io.prometheus.metrics.model.snapshots.Labels;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.context.LifecycleAutoConfiguration;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.info.ProjectInfoAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.sql.init.SqlInitializationAutoConfiguration;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.scheduling.annotation.EnableScheduling;
import picocli.CommandLine;
import picocli.spring.boot.autoconfigure.PicocliAutoConfiguration;

@SpringBootApplication()
@EnableScheduling
// speed up spring load time.
@ImportAutoConfiguration(value = {PicocliAutoConfiguration.class}, exclude = {
        ConfigurationPropertiesAutoConfiguration.class, ProjectInfoAutoConfiguration.class,
        PropertyPlaceholderAutoConfiguration.class, LifecycleAutoConfiguration.class,
        ApplicationAvailabilityAutoConfiguration.class, AopAutoConfiguration.class, JacksonAutoConfiguration.class,
        SqlInitializationAutoConfiguration.class, TaskExecutionAutoConfiguration.class})
public class Application implements CommandLineRunner, ExitCodeGenerator {
    private final CommandLine.IFactory factory;
    private final MainCommand command;
    private int exitCode;

    @Value("${application.version:0.0.0}")
    private String applicationVersion;

    @Value("${spring.application.name:nvd}")
    private String applicationName;

    Application(CommandLine.IFactory factory, MainCommand command) {
        this.factory = factory;
        this.command = command;
    }

    public static void main(String[] args) {
        String[] arguments = args;
        if (arguments.length == 0) {
            arguments = new String[]{"--help"};
        }
        System.exit(SpringApplication.exit(SpringApplication.run(Application.class, arguments)));
    }

    @Override
    public int getExitCode() {
        return exitCode;
    }

    @Override
    public void run(String... args) {
        Counter.builder().name("application").help("Information about the current project version and name")
                .constLabels(Labels.of("version", applicationVersion, "name", applicationName)).register().inc();

        // add extra line to make output more readable
        System.err.println();
        exitCode = new CommandLine(command, factory).setCaseInsensitiveEnumValuesAllowed(true).execute(args);
        System.err.println();
    }
}
