# nvd-lib & nvd cli

A [simple client](/nvd-lib) for the NVD API and a [simple cli](/app). Currently, only the Vulnerabilities API is implemented;
if the Products API is desired please open an issue or create a PR.

## NVD Links
* [Getting Started](https://nvd.nist.gov/developers/start-here)
* [Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
* [Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)

## Usage

Currently, the library is in development and has not been published in Maven Central. As such, the library can be built
using:

```shell
./gradlew clean build
```

The API is intended to be fairly simple; an example implementation is given below to retrieve the entire NVD CVE data
set - including a mechanism to keep the data up to date.

```java
import dev.jeremylong.nvdlib.NvdCveApi;
import dev.jeremylong.nvdlib.NvdCveApiBuilder;
import dev.jeremylong.nvdlib.nvd.DefCveItem;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Collection;

public class Example {

    long retrieveLastModifiedRequestEpoch() {
        //TODO implement a storage/retrieval mechanism for the epoch time.
        // if the last modified request epoch is not avaiable the method should return 0
        return 0;
    }

    void storeLastModifiedRequestEpoch(long epoch) {
        //TODO implement a storage/retrieval mechanism for the epoch time.
    }

    public void update() {
        long lastModifiedRequest = retrieveLastModifiedRequestEpoch();
        NvdCveApiBuilder builder = NvdCveApiBuilder.aNvdCveApi();
        if (lastModifiedRequest > 0) {
            LocalDateTime start = LocalDateTime.ofEpochSecond(lastModifiedRequest, 0, ZoneOffset.UTC);
            LocalDateTime end = start.minusDays(-120);
            builder.withLastModifiedFilter(start, end);
        }
        //TODO add API key with builder's `withApiKey()`
        //TODO add any additional filters via the builder's `withfilter()`
        try (NvdCveApi api = builder.build()) {
            while (api.hasNext()) {
                Collection<DefCveItem> items = api.next();
                //TODO do something with the items
            }
            lastModifiedRequest = api.getLastModifiedRequest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        storeLastModifiedRequestEpoch(lastModifiedRequest);
    }
}
```

## nvd cli

The cli is a spring-boot command line tool built with picocli. The example
below does run the setup - which creates both an nvd shell script and a completion
script. If using zsh, completion could be copied or linked into /etc/bash_completion.d (or
/usr/local/etc/bash_completion.d on a Mac); see [permanently installing completion](https://picocli.info/autocomplete.html#_installing_completion_scripts_permanently_in_bashzsh)
for more detais. We may add a brew formular in the future.

```bash
$ ./gradlew build
$ cd app/build/libs
$ ./nvd-1.0.0-SNAPSHOT.jar setup
$ . ./nvd.completion.sh
$ ./nvd cve --cveId CVE-2021-44228 --prettyPrint
```
