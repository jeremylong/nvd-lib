# Open Vulnerabiity Project

The Open Vulnerability Project is a collection of Java libraries and a CLI to work
with various vulnerability data-sources (NVD, GitHub Security Advisories, etc.).

- [open-vulnerability-clients](/open-vulnerability-clients) is a collection of clients to retrieve vulnerability data from various data-feeds and APIs.
- [open-vulnerability-store](/open-vulnerability-store) is a library that will transform the vulnerability data collected by the clients into a common schema and persist the data to a database using hibernate.
- [vulnz](/vulnz) a simple CLI that can be used to access the vulnerability sources and persist the data using the open-vulnerability-store.

## Upgrading from vuln-tools

The project started off called vuln-tools and the various APIs were seperated into
standalone JAR files. The project has been renamed to the Open Vulnerability Project.

- All of the client libraries are now in the [open-vulnerability-clients](/open-vulnerability-clients).
- Packages have been renamed/moved:
    - `io.github.jeremylong.ghsa.*` -> `io.github.jeremylong.openvulnerability.client.ghsa.*`
    - `io.github.jeremylong.nvdlib.*` -> 'io.github.jeremylong.openvulnerability.client.nvd.*'
    - `io.github.jeremylong.nvdlib.nvd` -> 'io.github.jeremylong.openvulnerability.client.nvd.*'
- The `NvdCveApi` class has been renamed to `NvdCveClient`.
