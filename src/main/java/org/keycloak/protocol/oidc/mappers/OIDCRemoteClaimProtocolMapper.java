package org.keycloak.protocol.oidc.mappers;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import static org.keycloak.broker.saml.mappers.UsernameTemplateMapper.TRANSFORMERS;

public class OIDCRemoteClaimProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    private static final TypeReference<List<StringPair>> MAP_TYPE_REPRESENTATION = new TypeReference<List<StringPair>>() {
    };
    private static final TypeReference<List<String>> LIST_TYPE_REPRESENTATION = new TypeReference<List<String>>() {
    };
    private static final Pattern SUBSTITUTION = Pattern.compile("\\$\\{([^}]+?)(?:\\s*\\|\\s*(\\S+)\\s*)?\\}");
    private static CloseableHttpClient client = HttpClientBuilder.create().build();

    private static final String CLAIMS = "remote.claims";
    private static final String ENDPOINT = "remote.url";
    private static final String METHOD = "remote.method";
    private static final String QUERY = "remote.query";
    private static final String HEADERS = "remote.headers";
    private static final String TOKEN = "remote.token";

    private final static String CACHED_CLAIMS = "oidc-remote-claim-protocol-mapper.claims";

    public static final String PROVIDER_ID = "oidc-remote-claim-protocol-mapper";

    static {
        ProviderConfigProperty claimsProperty = new ProviderConfigProperty();
        claimsProperty.setName(CLAIMS);
        claimsProperty.setLabel("Remote claims");
        claimsProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        claimsProperty.setHelpText("Remote claims to include in the token");

        configProperties.add(claimsProperty);

        ProviderConfigProperty endpointProperty = new ProviderConfigProperty();
        endpointProperty.setName(ENDPOINT);
        endpointProperty.setLabel("Endpoint");
        endpointProperty.setType(ProviderConfigProperty.STRING_TYPE);
        endpointProperty.setRequired(true);
        endpointProperty.setHelpText("Url of the remote claim provider");

        configProperties.add(endpointProperty);

        ProviderConfigProperty methodProperty = new ProviderConfigProperty();
        methodProperty.setName(METHOD);
        methodProperty.setLabel("Method");
        methodProperty.setType(ProviderConfigProperty.LIST_TYPE);
        methodProperty.setOptions(Arrays.asList("GET", "POST", "PUT"));
        methodProperty.setDefaultValue("GET");
        methodProperty.setHelpText("HTTP method used to retrieve remote claims");

        configProperties.add(methodProperty);

        ProviderConfigProperty queryProperty = new ProviderConfigProperty();
        queryProperty.setName(QUERY);
        queryProperty.setLabel("Query string parameters");
        queryProperty.setType(ProviderConfigProperty.MAP_TYPE);
        queryProperty.setHelpText("Query string parameters to include in the request");

        configProperties.add(queryProperty);

        ProviderConfigProperty headersProperty = new ProviderConfigProperty();
        headersProperty.setName(HEADERS);
        headersProperty.setLabel("Headers");
        headersProperty.setType(ProviderConfigProperty.MAP_TYPE);
        headersProperty.setHelpText("HTTP headers to include in the request");

        configProperties.add(headersProperty);

        ProviderConfigProperty tokenProperty = new ProviderConfigProperty();
        tokenProperty.setName(TOKEN);
        tokenProperty.setLabel("Include token in authorization header");
        tokenProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        tokenProperty.setDefaultValue("true");
        tokenProperty.setHelpText("Include partial token authorization header");

        configProperties.add(tokenProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OIDCRemoteClaimProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Remote claim mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Map remote claims to claims";
    }

    @Override
    protected void setClaim(IDToken idToken, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String token = null;
        if (useToken(mappingModel)) {
            token = keycloakSession.tokens().encode(idToken);
        }

        mapRemoteClaims(idToken.getOtherClaims(), mappingModel, userSession, clientSessionCtx, token);
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        mapRemoteClaims(accessTokenResponse.getOtherClaims(), mappingModel, userSession, clientSessionCtx,
                null);
    }

    private static void mapRemoteClaims(Map<String, Object> otherClaims, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx, String token) {
        JsonNode claims = clientSessionCtx.getAttribute(CACHED_CLAIMS, JsonNode.class);
        if (claims == null) {
            try {
                if ((claims = getRemoteClaims(mappingModel, userSession, clientSessionCtx, token)) == null) {
                    return;
                }
            } catch (ClientProtocolException e) {
                throw new RuntimeException("Could not retireve remote claims", e);
            } catch (IOException e) {
                throw new RuntimeException("Could not retireve remote claims", e);
            } catch (URISyntaxException e) {
                throw new RuntimeException("Could not retireve remote claims", e);
            }

            clientSessionCtx.setAttribute(CACHED_CLAIMS, claims);
        }

        final List<String> targetClaims = getTargetClaims(mappingModel);
        if (targetClaims.size() > 0) {
            for (String claim : targetClaims) {
                Object claimValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, claims.get(claim));
                if (claimValue != null) {
                    otherClaims.put(claim, claimValue);
                }
            }
        } else {
            for (Iterator<Entry<String, JsonNode>> field = claims.fields(); field.hasNext();) {
                final Entry<String, JsonNode> entry = field.next();
                final Object claimValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, entry.getValue());
                if (claimValue != null) {
                    otherClaims.put(entry.getKey(), claimValue);
                }
            }
        }
    }

    private static List<String> getTargetClaims(ProtocolMapperModel mappingModel) {
        final String configList = mappingModel.getConfig().get(CLAIMS);
        try {
            return JsonSerialization.readValue(configList, LIST_TYPE_REPRESENTATION);
        } catch (IOException e) {
            throw new RuntimeException("Could not deserialize json: " + configList, e);
        }
    }

    private static MultivaluedHashMap<String, String> getConfigMap(ProtocolMapperModel mappingModel, String configKey,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final MultivaluedHashMap<String, String> map = new MultivaluedHashMap<>();
        final String configMap = mappingModel.getConfig().get(configKey);

        try {
            final List<StringPair> keyValues = JsonSerialization.readValue(configMap, MAP_TYPE_REPRESENTATION);

            for (StringPair keyValue : keyValues) {
                final Matcher m = SUBSTITUTION.matcher(keyValue.value);
                final StringBuffer sb = new StringBuffer();

                while (m.find()) {
                    String variable = m.group(1).toLowerCase();
                    UnaryOperator<String> transformer = Optional.ofNullable(m.group(2)).map(TRANSFORMERS::get)
                            .orElse(UnaryOperator.identity());

                    if (variable.startsWith("user.")) {
                        String name = variable.substring("user.".length());
                        String value = userSession.getUser().getFirstAttribute(name);
                        m.appendReplacement(sb, transformer.apply(value == null ? "" : value));
                    } else if (variable.startsWith("client.")) {
                        String name = variable.substring("client.".length());
                        String value = null;

                        ClientModel client = clientSessionCtx.getClientSession().getClient();
                        if (name.equals("id")) {
                            value = client.getId();
                        } else if (name.equals("name")) {
                            value = client.getName();
                        } else {
                            value = client.getAttribute(name);
                        }

                        m.appendReplacement(sb, transformer.apply(value == null ? "" : value));
                    } else if (variable.startsWith("realm.")) {
                        String name = variable.substring("realm.".length());
                        String value = null;

                        RealmModel realm = userSession.getRealm();
                        if (name.equals("id")) {
                            value = realm.getId();
                        } else if (name.equals("name")) {
                            value = realm.getName();
                        } else {
                            value = realm.getAttribute(name);
                        }

                        m.appendReplacement(sb, transformer.apply(value == null ? "" : value));
                    } else if (variable.startsWith("session.")) {
                        String name = variable.substring("session.".length());
                        String value = userSession.getNote(name);
                        m.appendReplacement(sb, transformer.apply(value == null ? "" : value));
                    } else if (variable.equals("scope")) {
                        m.appendReplacement(sb, transformer.apply(clientSessionCtx.getScopeString()));
                    } else {
                        m.appendReplacement(sb, m.group(1));
                    }
                }

                map.add(keyValue.key, m.appendTail(sb).toString());
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not deserialize json: " + configMap, e);
        }

        return map;
    }

    private static JsonNode getRemoteClaims(ProtocolMapperModel mappingModel, UserSessionModel userSession,
            ClientSessionContext clientSessionCtx, String token)
            throws ClientProtocolException, IOException, URISyntaxException {
        // Get parameters
        final MultivaluedHashMap<String, String> query = getConfigMap(mappingModel, QUERY, userSession,
                clientSessionCtx);
        // Get headers
        final MultivaluedHashMap<String, String> headers = getConfigMap(mappingModel, HEADERS, userSession,
                clientSessionCtx);

        URIBuilder url = new URIBuilder(mappingModel.getConfig().get(ENDPOINT));

        // Build parameters
        for (Map.Entry<String, List<String>> param : query.entrySet()) {
            for (String value : param.getValue()) {
                url = url.addParameter(param.getKey(), value);
            }
        }

        HttpUriRequest request;
        final String method = mappingModel.getConfig().get(METHOD);
        if (method.equalsIgnoreCase("GET")) {
            request = new HttpGet(url.build());
        } else if (method.equalsIgnoreCase("POST")) {
            request = new HttpPost(url.build());
        } else if (method.equalsIgnoreCase("PUT")) {
            request = new HttpPut(url.build());
        } else {
            throw new RuntimeException(method + " is not a supported http method");
        }

        // Build headers
        for (Map.Entry<String, List<String>> param : headers.entrySet()) {
            for (String value : param.getValue()) {
                request.addHeader(param.getKey(), value);
            }
        }

        if (token != null) {
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }

        request.addHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);

        HttpResponse response = client.execute(request);

        int code = response.getStatusLine().getStatusCode();
        if (code != 200) {
            throw new RuntimeException("Wrong status received for remote claim - Expected: 200, Received: "
                    + code);
        }

        InputStream responseStream = response.getEntity().getContent();

        try {
            final JsonNode result = JsonSerialization.readValue(responseStream, JsonNode.class);
            if (!result.isObject()) {
                return null;
            }

            return result;
        } finally {
            responseStream.close();
        }
    }

    private static boolean useToken(ProtocolMapperModel mappingModel) {
        return "true".equals(mappingModel.getConfig().get(TOKEN));
    }

    static class StringPair {
        private String key;
        private String value;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
