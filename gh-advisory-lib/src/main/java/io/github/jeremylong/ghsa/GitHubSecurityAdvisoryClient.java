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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.Template;
import io.github.jeremylong.vulntools.PagedDataSource;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.routing.SystemDefaultRoutePlanner;
import org.apache.hc.core5.http.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class GitHubSecurityAdvisoryClient implements PagedDataSource<SecurityAdvisory> {
    public static final String GITHUB_GRAPHQL_ENDPOINT = "https://api.github.com/graphql";
    /**
     * Reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(GitHubSecurityAdvisoryClient.class);
    /**
     * The mustache template to retrieve advisories.
     */
    private final static String ADVISORIES_TEMPLATE = "securityAdvisories.mustache";
    /**
     * The mustache template to retrieve advisory vulnerabilities.
     */
    private final static String VULNERABILITIES_TEMPLATE = "securityAdvisoryVulnerabilities.mustache";
    /**
     * The mustache template to retrieve advisory CWEs.
     */
    private final static String CWES_TEMPLATE = "securityAdvisoryCwes.mustache";
    /**
     * HTTP Client to access the API.
     */
    private final CloseableHttpAsyncClient httpClient;
    /**
     * Jackson JSON object mapper.
     */
    private final ObjectMapper objectMapper;
    /**
     * Template for security advisories.
     */
    private final Template advistoriesTemplate;
    /**
     * Template for security advisory's vulnerabilities - in case we have more than 100.
     */
    private final Template vulnerabilitiesTemplate;
    /**
     * Template for security advisory's CWEs - in case we have more than 50.
     */
    private final Template cwesTemplate;
    /**
     * Has the first HTTP call been made?
     */
    private boolean firstCall = true;
    /**
     * The last HTTP status code received.
     */
    private int lastStatusCode = 200;
    /**
     * The total count of advisories being retrieved.
     */
    private int totalCount = 0;
    /**
     * Asynchronous future HTTP Response.
     */
    private Future<SimpleHttpResponse> futureResponse;

    /**
     * The GitHub GraphQL endpoint.
     */
    private String endpoint;
    /**
     * The GitHub Access Token.
     */
    private String githubToken;
    /**
     * The updatedSince filter.
     */
    private String updatedSinceFilter;
    /**
     * The publishedSince filter.
     */
    private String publishedSinceFilter;

    /**
     * The last updated date time value retrieved.
     */
    private ZonedDateTime lastUpdated;

    /**
     * Constructs a new client.
     *
     * @param githubToken the GitHub API Token.
     */
    public GitHubSecurityAdvisoryClient(String githubToken) {
        this(githubToken, GITHUB_GRAPHQL_ENDPOINT);
    }

    /**
     * Constructs a new client.
     *
     * @param endpoint the GraphQL endpoint of GitHub or GHE.
     * @param githubToken the GitHub API Token.
     */
    public GitHubSecurityAdvisoryClient(String githubToken, String endpoint) {
        this.githubToken = githubToken;
        this.endpoint = endpoint;
        advistoriesTemplate = loadMustacheTemplate(ADVISORIES_TEMPLATE);
        vulnerabilitiesTemplate = loadMustacheTemplate(VULNERABILITIES_TEMPLATE);
        cwesTemplate = loadMustacheTemplate(CWES_TEMPLATE);
        // httpClient = HttpAsyncClients.createDefault();
        SystemDefaultRoutePlanner planner = new SystemDefaultRoutePlanner(ProxySelector.getDefault());
        httpClient = HttpAsyncClients.custom().setRoutePlanner(planner).build();
        httpClient.start();
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Loads a mustache template from the project's resources by name.
     *
     * @param resourceName the name of the template.
     * @return the mustache template.
     */
    private Template loadMustacheTemplate(String resourceName) {
        String template = null;
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourceName);
                InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
                BufferedReader reader = new BufferedReader(isr)) {
            template = reader.lines().collect(Collectors.joining(System.lineSeparator()));

        } catch (IOException e) {
            throw new GitHubSecurityAdvisoryException(e);
        }
        return Mustache.compiler().escapeHTML(false).compile(template);
    }

    /**
     * Filter the Security Advisories by those updated since the give date time.
     *
     * @param utcUpdatedSinceFilter the date to filter on.
     */
    public void setUpdatedSinceFilter(ZonedDateTime utcUpdatedSinceFilter) {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        this.updatedSinceFilter = utcUpdatedSinceFilter.format(dtf);
    }

    /**
     * Filter the Security Advisories by those published since the give date time.
     *
     * @param utcPublishedSinceFilter the date to filter on.
     */
    public void setPublishedSinceFilter(ZonedDateTime utcPublishedSinceFilter) {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        this.publishedSinceFilter = utcPublishedSinceFilter.format(dtf);
    }

    /**
     * Internal API to query the endpoint.
     *
     * @param json the GraphQL query body (i.e. minus the query:).
     * @return the Asynchronous HTTP Response.
     */
    private Future<SimpleHttpResponse> query(String json) {
        ObjectNode jsonObj = objectMapper.createObjectNode();
        jsonObj.put("query", json);
        String query = null;
        try {
            query = objectMapper.writeValueAsString(jsonObj);
        } catch (JsonProcessingException e) {
            throw new GitHubSecurityAdvisoryException("Unable to convert template to quer", e);
        }
        SimpleRequestBuilder builder = SimpleRequestBuilder.post(endpoint);
        builder.addHeader("Authorization", "bearer " + githubToken);
        builder.addHeader("User-Agent", "gh-advisory-lib");
        builder.setBody(query, ContentType.APPLICATION_JSON);
        final SimpleHttpRequest request = builder.build();
        return httpClient.execute(request, new SimpleFutureResponse());
    }

    /**
     * Cleanup allocated resources.
     *
     * @throws Exception thrown if there is a problem.
     */
    @Override
    public void close() throws Exception {
        httpClient.close();
    }

    /**
     * Returns the last HTTP Status Code received.
     *
     * @return the last HTTP Status Code received.
     */
    public int getLastStatusCode() {
        return lastStatusCode;
    }

    /**
     * Returns <code>true</code> if there are more records available; otherwise <code>false</code>.
     *
     * @return <code>true</code> if there are more records available; otherwise <code>false</code>.
     */
    @Override
    public boolean hasNext() {
        if (lastStatusCode != 200) {
            return false;
        }
        return firstCall || futureResponse != null;
    }

    /**
     * Returns the next list of security advisories.
     *
     * @return a list of security advisories.
     */
    @Override
    public Collection<SecurityAdvisory> next() {
        try {
            Map<String, String> data = new HashMap<String, String>();
            if (updatedSinceFilter != null) {
                data.put("updatedSince", updatedSinceFilter);
            }
            if (publishedSinceFilter != null) {
                data.put("publishedSince", publishedSinceFilter);
            }
            // after should be the endCursor of the previous request - leave out for the first request
            // data.put("after","asdfadfasdfasfawefqwe");
            if (firstCall) {
                firstCall = false;
                futureResponse = query(advistoriesTemplate.execute(data));
            }
            SimpleHttpResponse response = null;
            response = futureResponse.get();
            if (response.getCode() == 200) {
                String body = response.getBodyText();
                if (body == null) {
                    body = new String(response.getBodyBytes(), StandardCharsets.UTF_8);
                }
                SecurityAdvisories results = objectMapper.readValue(body, SecurityAdvisories.class);
                List<SecurityAdvisory> list = results.getSecurityAdvisories();
                totalCount += list.size();
                if (results.getPageInfo().isHasNextPage() || totalCount < results.getTotalCount()) {
                    data.put("after", results.getPageInfo().getEndCursor());
                    futureResponse = query(advistoriesTemplate.execute(data));
                } else {
                    futureResponse = null;
                }

                ensureSubPages(list);

                lastUpdated = findLastUpdated(lastUpdated, list);

                return list;
            } else {
                lastStatusCode = response.getCode();
                String error = new String(response.getBodyBytes(), StandardCharsets.UTF_8);
                LOG.error(error);
            }
        } catch (InterruptedException e) {
            Thread.interrupted();
            LOG.debug("Interrupted", e);
            throw new GitHubSecurityAdvisoryException(e);
        } catch (ExecutionException | JsonProcessingException e) {
            LOG.debug(e.getMessage(), e);
            throw new GitHubSecurityAdvisoryException(e);
        }
        return null;
    }

    /**
     * Returns the latest updated date.
     *
     * @return the lastest updated date
     */
    public ZonedDateTime getLastUpdated() {
        return lastUpdated;
    }

    /**
     * Retrieve the latest last updated date from the list of security advisories.
     *
     * @param lastUpdatedDate the last updated date.
     * @param list the list of security advisories.
     * @return the latest last published date.
     */
    private ZonedDateTime findLastUpdated(ZonedDateTime lastUpdatedDate, List<SecurityAdvisory> list) {
        ZonedDateTime current = lastUpdatedDate;
        for (SecurityAdvisory adv : list) {
            if (current == null || current.compareTo(adv.getUpdatedAt()) < 0) {
                current = adv.getUpdatedAt();
            }
        }
        return current;
    }

    /**
     * Ensure that the CWE and Vulnerability lists have been completely fetched and requests any missing entries.
     *
     * @param list the list of security advisories to validate and if necassary add CWE or vulnerability data.
     * @throws ExecutionException thrown if there is a problem.
     * @throws InterruptedException thrown if interrupted.
     */
    private void ensureSubPages(List<SecurityAdvisory> list) throws ExecutionException, InterruptedException {
        for (SecurityAdvisory sa : list) {
            if (sa.getCwes().getPageInfo().isHasNextPage() || sa.getCwes().getTotalCount() > 50) {
                LOG.debug("Retrieiving additional CWEs for " + sa.getGhsaId());
                int count = 50;
                int max = sa.getCwes().getTotalCount();
                String after = sa.getCwes().getPageInfo().getEndCursor();
                while (count < max) {
                    SecurityAdvisoryResponse results = fetch(cwesTemplate, sa.getGhsaId(), after);
                    CWEs cwes = results.getSecurityAdvisory().getCwes();
                    count += cwes.getEdges().size();
                    max = cwes.getTotalCount();
                    after = cwes.getPageInfo().getEndCursor();
                    sa.getCwes().addCwes(cwes.getEdges());
                }
            }
            if (sa.getVulnerabilities().getPageInfo().isHasNextPage()
                    || sa.getVulnerabilities().getTotalCount() > 100) {
                LOG.debug("Retrieiving additional Vulnerabilities for " + sa.getGhsaId());
                int count = 100;
                int max = sa.getVulnerabilities().getTotalCount();
                String after = sa.getVulnerabilities().getPageInfo().getEndCursor();
                while (count < max) {
                    SecurityAdvisoryResponse results = fetch(vulnerabilitiesTemplate, sa.getGhsaId(), after);
                    Vulnerabilities vulnerability = results.getSecurityAdvisory().getVulnerabilities();
                    count += vulnerability.getEdges().size();
                    max = vulnerability.getTotalCount();
                    after = vulnerability.getPageInfo().getEndCursor();
                    sa.getVulnerabilities().addVulnerabilties(vulnerability.getEdges());
                }
            }
        }
    }

    /**
     * Fetches additional data from the GraphQL API.
     *
     * @param template the template to use for the request.
     * @param ghsaId the advisory id used to filter the request.
     * @param after the end cursor from the previous request.
     * @return the requested data.
     * @throws ExecutionException thrown if there is a problem.
     * @throws InterruptedException thrown if interrupted.
     */
    private SecurityAdvisoryResponse fetch(Template template, String ghsaId, String after)
            throws InterruptedException, ExecutionException {
        SecurityAdvisoryResponse results = null;
        try {
            Map<String, String> data = new HashMap<String, String>();
            data.put("ghsaId", ghsaId);
            data.put("after", after);
            Future<SimpleHttpResponse> future = query(template.execute(data));
            SimpleHttpResponse response = future.get();
            String body = response.getBodyText();
            if (body == null) {
                body = new String(response.getBodyBytes(), StandardCharsets.UTF_8);
            }
            results = objectMapper.readValue(body, SecurityAdvisoryResponse.class);
        } catch (JsonProcessingException e) {
            LOG.debug("Deserialization Error", e);
            throw new GitHubSecurityAdvisoryException(e);
        }
        return results;
    }
}
