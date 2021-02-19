package fr.benjaminfavre.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    private String userJson;

    public AppleIdentityProvider(KeycloakSession session, AppleIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl("https://appleid.apple.com/auth/authorize?response_mode=form_post");
        config.setTokenUrl("https://appleid.apple.com/auth/token");
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event);
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext context = super.getFederatedIdentity(response);
        logDebugText("getFederatedIdentity response", response);
        logDebugText("getFederatedIdentity context", context);
        if (userJson != null) {
            try {
                User user = JsonSerialization.readValue(userJson, User.class);
                context.setEmail(user.email);
                context.setFirstName(user.name.firstName);
                context.setLastName(user.name.lastName);
            } catch (IOException e) {
                logger.errorf("Failed to parse userJson [%s]: %s", userJson, e);
            }
        }

        return context;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        AppleIdentityProviderConfig config = (AppleIdentityProviderConfig) getConfig();
        tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId());
        String base64PrivateKey = config.getClientSecret();

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] pkc8ePrivateKey = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkc8ePrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm(Algorithm.ES256);
            keyWrapper.setKid(config.getKeyId());
            keyWrapper.setPrivateKey(privateKey);
            SignatureSignerContext signer = new ServerECDSASignatureSignerContext(keyWrapper);

            long currentTime = Time.currentTime();
            JsonWebToken token = new JsonWebToken();
            token.issuer(config.getTeamId());
            token.iat(currentTime);
            token.exp(currentTime + 15 * 60);
            token.audience("https://appleid.apple.com");
            token.subject(config.getClientId());
            String clientSecret = new JWSBuilder().jsonContent(token).sign(signer);

            tokenRequest.param(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.errorf("Failed to generate client secret: %s", e);
        }

        return tokenRequest;
    }

    @Override
    protected String getDefaultScopes() {
        return "email name";
    }

    protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @POST
        public Response authResponse(
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                @FormParam("user") String userJson,
                @FormParam(OAuth2Constants.ERROR) String error) {
            AppleIdentityProvider.this.userJson = userJson;
            return super.authResponse(state, authorizationCode, error);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class User {
        public String email;
        public Name name;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Name {
            public String firstName;
            public String lastName;
        }
    }

    // Overrided funs for debugging

    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        Response response = super.exchangeStoredToken(uriInfo, event, authorizedClient, tokenUserSession, tokenSubject);
        logDebugText("exchangeStoredToken uriInfo", uriInfo);
        logDebugText("exchangeStoredToken event", event);
        logDebugText("exchangeStoredToken tokenUserSession", tokenUserSession);
        logDebugText("exchangeStoredToken tokenSubject", tokenSubject);
        logDebugText("exchangeStoredToken response", response);
        return response;
    }

    @Override
    protected void processAccessTokenResponse(BrokeredIdentityContext context, AccessTokenResponse response) {
        logDebugText("processAccessTokenResponse context", context);
        logDebugText("processAccessTokenResponse response", response);
        super.processAccessTokenResponse(context, response);
    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        Response response = super.exchangeSessionToken(uriInfo, event, authorizedClient, tokenUserSession, tokenSubject);
        logDebugText("exchangeSessionToken uriInfo", uriInfo);
        logDebugText("exchangeSessionToken tokenUserSession", tokenUserSession);
        logDebugText("exchangeSessionToken tokenSubject", tokenSubject);
        logDebugText("exchangeSessionToken response", response);
        return response;
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {
        BrokeredIdentityContext context = super.extractIdentity(tokenResponse, accessToken, idToken);
        logDebugText("extractIdentity accessToken", accessToken);
        logDebugText("extractIdentity idToken", idToken);
        logDebugText("extractIdentity context", context);
        return context;
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        logDebugText("authenticationFinished authSession", authSession);
        logDebugText("authenticationFinished context", context);
        super.authenticationFinished(authSession, context);
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        String validate = super.getProfileEndpointForValidation(event);
        logDebugText("getProfileEndpointForValidation event", event);
        logDebugText("getProfileEndpointForValidation validate", validate);
        return validate;
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, BrokeredIdentityContext context) {
        logDebugText("preprocessFederatedIdentity session", session);
        logDebugText("preprocessFederatedIdentity realm", realm);
        logDebugText("preprocessFederatedIdentity context", context);
        super.preprocessFederatedIdentity(session, realm, context);
    }

    @Override
    public Response exchangeFromToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject, MultivaluedMap<String, String> params) {
        Response response = super.exchangeFromToken(uriInfo, event, authorizedClient, tokenUserSession, tokenSubject, params);
        logDebugText("exchangeFromToken uriInfo", uriInfo);
        logDebugText("exchangeFromToken tokenUserSession", tokenUserSession);
        logDebugText("exchangeFromToken tokenSubject", tokenSubject);
        logDebugText("exchangeFromToken event", event);
        logDebugText("exchangeFromToken response", response);
        return response;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        logDebugText("importNewUser session", session);
        logDebugText("importNewUser realm", realm);
        logDebugText("importNewUser user", user);
        logDebugText("importNewUser context", context);
        super.importNewUser(session, realm, user, context);
    }

    @Override
    protected Response exchangeErrorResponse(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, String errorCode, String reason) {
        Response response = super.exchangeErrorResponse(uriInfo, authorizedClient, tokenUserSession, errorCode, reason);
        logDebugText("exchangeErrorResponse uriInfo", uriInfo);
        logDebugText("exchangeErrorResponse tokenUserSession", tokenUserSession);
        logDebugText("exchangeErrorResponse errorCode", errorCode);
        logDebugText("exchangeErrorResponse reason", reason);
        logDebugText("exchangeErrorResponse response", response);
        return response;
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        logDebugText("updateBrokeredUser session", session);
        logDebugText("updateBrokeredUser realm", realm);
        logDebugText("updateBrokeredUser user", user);
        logDebugText("updateBrokeredUser context", context);
        super.updateBrokeredUser(session, realm, user, context);
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode userInfo) {
        BrokeredIdentityContext identityContext = super.extractIdentityFromProfile(event, userInfo);
        logDebugText("extractIdentityFromProfile userInfo", userInfo);
        logDebugText("extractIdentityFromProfile Context", identityContext);
        return identityContext;
    }

    @Override
    protected BrokeredIdentityContext validateExternalTokenThroughUserInfo(EventBuilder event, String subjectToken, String subjectTokenType) {
        BrokeredIdentityContext identityContext = super.validateExternalTokenThroughUserInfo(event, subjectToken, subjectTokenType);
        logDebugText("validateExternalTokenThroughUserInfo Context", identityContext);
        return identityContext;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        BrokeredIdentityContext identityContext = super.doGetFederatedIdentity(accessToken);
        logDebugText("doGetFederatedIdentity Token", accessToken);
        logDebugText("doGetFederatedIdentity Context", identityContext);
        return identityContext;
    }

    @Override
    protected JsonWebToken validateToken(String encodedToken) {
        logDebugText("JsonWebToken", encodedToken);
        JsonWebToken token = super.validateToken(encodedToken);

        logDebugText("JsonWebToken:isActive", token.isActive());
        logDebugText("JsonWebToken:isExpired", token.isExpired());
        logDebugText("JsonWebToken:getOtherClaims", token.getOtherClaims());
        return token;
    }

    @Override
    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        logDebugText("JsonWebTokenWithIgnoreAudience", encodedToken);
        JsonWebToken token = super.validateToken(encodedToken, ignoreAudience);
        logDebugText("JsonWebTokenWithIgnoreAudience:isActive", token.isActive());
        logDebugText("JsonWebTokenWithIgnoreAudience:isExpired", token.isExpired());
        logDebugText("JsonWebTokenWithIgnoreAudience:getOtherClaims", token.getOtherClaims());
        return token;
    }

    private void logDebugText(String functionName, Object parameter) {
        logger.debugf("AppleIdentityProvider: %s, " + functionName, parameter);
    }
}
