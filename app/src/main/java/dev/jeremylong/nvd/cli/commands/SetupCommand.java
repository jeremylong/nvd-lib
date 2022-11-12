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
package dev.jeremylong.nvd.cli.commands;

import com.diogonunes.jcolor.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import static com.diogonunes.jcolor.Ansi.colorize;

@Component
@CommandLine.Command(name = "setup", description = "Extracts a shell script and completion script to the current directory to make calling the CLI easier")
public class SetupCommand extends AbstractHelpfulCommand {
    /**
     * Reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SetupCommand.class);

    @Autowired
    private ResourceLoader resourceLoader;

    @Override
    public Integer call() throws Exception {
        Resource nvd = resourceLoader.getResource("classpath:nvd");

        Resource completion = resourceLoader.getResource("classpath:nvd.completion.sh");

        if (nvd.exists()) {
            Path destination = Paths.get("./nvd");
            InputStream in = Channels.newInputStream(nvd.readableChannel());
            Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
            destination.toFile().setExecutable(true);
        } else {
            LOG.error("Unable to setup the app: {}", nvd);
        }
        if (completion.exists()) {
            Path destination = Paths.get("./nvd.completion.sh");
            InputStream in = Channels.newInputStream(completion.readableChannel());
            Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
        } else {
            LOG.error("Unable to setup the completion file: {}", completion);
        }

        LOG.info(colorize("Setup complete", Attribute.GREEN_TEXT()));
        return 0;
    }
}
