package io.jenkins.plugins.entraoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.jenkins.plugins.credentials.oauth.OAuth2CapabilityScopeResolver;
import com.google.jenkins.plugins.credentials.oauth.OAuth2Credentials;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeCapability;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeRequirement;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Tests for {@link EntraCapabilityScopeResolver}.
 */
class EntraCapabilityScopeResolverTest {

    private final EntraCapabilityScopeResolver resolver = new EntraCapabilityScopeResolver();

    @Test
    void isApplicableToEntraCredentials() {
        assertTrue(resolver.isApplicable(EntraOAuthCredentials.class));
    }

    @Test
    void isNotApplicableToUnrelatedCredentialsType() {
        assertFalse(resolver.isApplicable(UnrelatedOAuth2Credentials.class));
    }

    @Test
    void resolvesSendEmailToOutlookDefaultScope() {
        EntraOAuth2ScopeRequirement requirement =
                resolver.resolveRequirement(List.of(OAuth2ScopeCapability.SEND_EMAIL));

        assertEquals(Set.of(EntraCapabilityScopeResolver.OUTLOOK_DEFAULT_SCOPE), Set.copyOf(requirement.getScopes()));
    }

    @Test
    void resolvesMultipleKnownCapabilitiesToTheSameSingleDefaultScope() {
        EntraOAuth2ScopeRequirement requirement = resolver.resolveRequirement(
                List.of(OAuth2ScopeCapability.SEND_EMAIL));

        // client-credentials always exactly one scope, regardless of
        // how many capabilities were requested, since Exchange Online uses one resource ".default" scope
        assertEquals(1, requirement.getScopes().size());
        assertEquals(EntraCapabilityScopeResolver.OUTLOOK_DEFAULT_SCOPE, requirement.getScopes().iterator().next());
    }

    @Test
    void returnsNullForUnsupportedCustomCapability() {
        EntraOAuth2ScopeRequirement requirement =
                resolver.resolveRequirement(List.of(OAuth2ScopeCapability.of("READ_CALENDAR")));

        assertNull(requirement);
    }

    @Test
    void returnsNullIfAnyRequestedCapabilityIsUnsupported() {
        EntraOAuth2ScopeRequirement requirement = resolver.resolveRequirement(
                List.of(OAuth2ScopeCapability.SEND_EMAIL, OAuth2ScopeCapability.of("READ_CALENDAR")));

        assertNull(requirement);
    }

    /**
     * Verifies the resolver is actually discoverable through the public API a
     * consumer like email-ext uses - {@code @Extension} + {@code ExtensionList}
     */
    @Nested
    @WithJenkins
    static class Discovery {

        @Test
        void isDiscoveredViaResolveForEntraCredentials(JenkinsRule ignored) {
            OAuth2ScopeRequirement requirement = OAuth2CapabilityScopeResolver.resolve(
                    EntraOAuthCredentials.class, List.of(OAuth2ScopeCapability.SEND_EMAIL));

            assertEquals(
                    Set.of(EntraCapabilityScopeResolver.OUTLOOK_DEFAULT_SCOPE), Set.copyOf(requirement.getScopes()));
        }

        @Test
        void isDiscoveredButReturnsNullForUnsupportedCapability(JenkinsRule ignored) {
            OAuth2ScopeRequirement requirement = OAuth2CapabilityScopeResolver.resolve(
                    EntraOAuthCredentials.class, List.of(OAuth2ScopeCapability.of("READ_CALENDAR")));

            assertNull(requirement);
        }
    }

    /**
     * Minimal stand-in credentials type so {@link #isNotApplicableToUnrelatedCredentialsType()}
     * doesn't need a second real provider plugin on the test classpath. Never instantiated.
     */
    private abstract static class UnrelatedOAuth2Credentials implements OAuth2Credentials<OAuth2ScopeRequirement> {}
}