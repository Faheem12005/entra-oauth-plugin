package io.jenkins.plugins.entraoauth;

import com.google.jenkins.plugins.credentials.oauth.OAuth2Credentials;
import com.google.jenkins.plugins.credentials.oauth.OAuth2CapabilityScopeResolver;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeCapability;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.util.Collection;
import java.util.Set;

/**
 * Resolves {@link OAuth2ScopeCapability} for {@link EntraOAuthCredentials}.
 */
@Extension
public class EntraCapabilityScopeResolver extends OAuth2CapabilityScopeResolver {

    static final String OUTLOOK_DEFAULT_SCOPE = "https://outlook.office365.com/.default";

    /**
     * Set of OAuth2 capabilities supported by Entra OAuth credentials.
     */
    private static final Set<OAuth2ScopeCapability> SUPPORTED_CAPABILITIES =
            Set.of(OAuth2ScopeCapability.SEND_EMAIL);

    @Override
    public boolean isApplicable(@NonNull Class<? extends OAuth2Credentials<?>> credentialsType) {
        return EntraOAuthCredentials.class.isAssignableFrom(credentialsType);
    }

    @Override
    @CheckForNull
    public EntraOAuth2ScopeRequirement resolveRequirement(
            @NonNull Collection<OAuth2ScopeCapability> capabilities) {
        for (OAuth2ScopeCapability capability : capabilities) {
            if (!SUPPORTED_CAPABILITIES.contains(capability)) {
                return null;
            }
        }
        return new EntraOAuth2ScopeRequirement(Set.of(OUTLOOK_DEFAULT_SCOPE));
    }
}