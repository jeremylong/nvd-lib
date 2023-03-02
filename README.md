# vuln-tools

- [java NVD API client](/nvd-lib)
  - Currently, only the NVD Vulnerabilities API is implemented; if the Products API is desired please open an issue or create a PR.
- [java GitHub Security Advisories client](/gh-advisory-lib)
- [simple vulnz cli](/vulnz).

In the future additional java client will be built to support other vulnerability sources.

## NVD Links
 
- [Getting Started](https://nvd.nist.gov/developers/start-here)
- [Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
- [Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)

## GitHub Security Advisory Links

- [GitHub Security Advisory Database](https://docs.github.com/en/enterprise-cloud@latest/code-security/security-advisories/global-security-advisories/browsing-security-advisories-in-the-github-advisory-database)
- [Explorer](https://docs.github.com/en/graphql/overview/explorer)

## vulnz cli

The vulnz cli is a wrapper around the `nvd-lib` and `gh-advisory-lib` that allows
users to download data from the APIs. The `gh-advisory-lib` requires the use of a
GitHub Personal Access Token. It is highly recommended to obtain a API Key for the
NVD.

### Database output

If you use the `-o` parameter to output into a file that has a `.db` extension,
it will append the records to a sqlite database of that name. Note that this
feature is experimental, and still expected to change, including the database
schema - so you might have to delete any database created with a previous
version of this tool.

# about

The cli is a spring-boot command line tool built with picocli. The example
below does run the setup - which creates both the `vulnz` symlink (in `/usr/local/bin`)
and a completion script. If using zsh, the completion will be added to 
`/etc/bash_completion.d` or `/usr/local/etc/bash_completion.d` (depending
on if they exist); see [permanently installing completion](https://picocli.info/autocomplete.html#_installing_completion_scripts_permanently_in_bashzsh)
for more details. We may add a brew formula in the future.

After running `install` you may need to restart your shell for the completion to work.

```bash
$ ./gradlew build
$ cd vulnz/build/libs
$ ./vulnz-1.0.0.jar install
$ vulnz cve --cveId CVE-2021-44228 --prettyPrint
```

Example of using the CLI with an API key stored in 1password using
the `op` CLI (see [getting started with op](https://developer.1password.com/docs/cli/get-started/)):

```bash
export NVD_API_KEY=op://vaultname/nvd-api/credential
eval $(op signin)
op run -- vulnz cve --threads 4 > cve-complete.json
```
