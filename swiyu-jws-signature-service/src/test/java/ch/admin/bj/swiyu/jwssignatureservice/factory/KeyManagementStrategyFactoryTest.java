package ch.admin.bj.swiyu.jwssignatureservice.factory;

import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.IKeyManagementStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for KeyManagementStrategyFactory.
 * Tests the retrieval of strategies and error handling for unsupported methods.
 */
class KeyManagementStrategyFactoryTest {

    private KeyManagementStrategyFactory factory;
    private Map<String, IKeyManagementStrategy> strategyMap;
    private IKeyManagementStrategy keyStrategy;
    private IKeyManagementStrategy pkcs11Strategy;
    private IKeyManagementStrategy securosysStrategy;

    @BeforeEach
    void setUp() {
        keyStrategy = mock(IKeyManagementStrategy.class);
        pkcs11Strategy = mock(IKeyManagementStrategy.class);
        securosysStrategy = mock(IKeyManagementStrategy.class);

        strategyMap = new HashMap<>();
        strategyMap.put("key", keyStrategy);
        strategyMap.put("pkcs11", pkcs11Strategy);
        strategyMap.put("securosys", securosysStrategy);

        factory = new KeyManagementStrategyFactory(strategyMap);
    }

    /**
     * Tests that getStrategy returns the correct KeyStrategy for "key" method.
     */
    @Test
    @DisplayName("getStrategy() returns KeyStrategy for 'key' method")
    void getStrategy_withKeyMethod_returnsKeyStrategy() {
        // When
        IKeyManagementStrategy result = factory.getStrategy("key");

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(keyStrategy);
    }

    /**
     * Tests that getStrategy returns the correct PKCS11Strategy for "pkcs11" method.
     */
    @Test
    @DisplayName("getStrategy() returns PKCS11Strategy for 'pkcs11' method")
    void getStrategy_withPkcs11Method_returnsPkcs11Strategy() {
        // When
        IKeyManagementStrategy result = factory.getStrategy("pkcs11");

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(pkcs11Strategy);
    }

    /**
     * Tests that getStrategy returns the correct SecurosysStrategy for "securosys" method.
     */
    @Test
    @DisplayName("getStrategy() returns SecurosysStrategy for 'securosys' method")
    void getStrategy_withSecurosysMethod_returnsSecurosysStrategy() {
        // When
        IKeyManagementStrategy result = factory.getStrategy("securosys");

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(securosysStrategy);
    }

    /**
     * Tests that getStrategy throws IllegalArgumentException for unsupported method.
     */
    @Test
    @DisplayName("getStrategy() throws IllegalArgumentException for unsupported method")
    void getStrategy_withUnsupportedMethod_throwsException() {
        // When/Then
        assertThatThrownBy(() -> factory.getStrategy("unsupported"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: unsupported");
    }

    /**
     * Tests that getStrategy throws IllegalArgumentException for null method.
     */
    @Test
    @DisplayName("getStrategy() throws IllegalArgumentException for null method")
    void getStrategy_withNullMethod_throwsException() {
        // When/Then
        assertThatThrownBy(() -> factory.getStrategy(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: null");
    }

    /**
     * Tests that getStrategy throws IllegalArgumentException for empty method.
     */
    @Test
    @DisplayName("getStrategy() throws IllegalArgumentException for empty method")
    void getStrategy_withEmptyMethod_throwsException() {
        // When/Then
        assertThatThrownBy(() -> factory.getStrategy(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: ");
    }

    /**
     * Tests that getStrategy handles case sensitivity correctly.
     */
    @Test
    @DisplayName("getStrategy() is case-sensitive")
    void getStrategy_isCaseSensitive() {
        // When/Then - uppercase should not match
        assertThatThrownBy(() -> factory.getStrategy("KEY"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: KEY");

        assertThatThrownBy(() -> factory.getStrategy("Key"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: Key");
    }

    /**
     * Tests that default constructor creates instance with null strategy map.
     */
    @Test
    @DisplayName("default constructor creates instance with null strategy map")
    void defaultConstructor_createsInstanceWithNullMap() {
        // When
        KeyManagementStrategyFactory defaultFactory = new KeyManagementStrategyFactory();

        // Then - calling getStrategy should throw NullPointerException
        assertThatThrownBy(() -> defaultFactory.getStrategy("key"))
                .isInstanceOf(NullPointerException.class);
    }

    /**
     * Tests that factory works with empty strategy map.
     */
    @Test
    @DisplayName("factory with empty map throws exception for any method")
    void factory_withEmptyMap_throwsExceptionForAnyMethod() {
        // Given
        KeyManagementStrategyFactory emptyFactory = new KeyManagementStrategyFactory(new HashMap<>());

        // When/Then
        assertThatThrownBy(() -> emptyFactory.getStrategy("key"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported key management method: key");
    }

    /**
     * Tests that factory can handle adding new strategies dynamically.
     */
    @Test
    @DisplayName("factory works with custom strategy added to map")
    void getStrategy_withCustomStrategy_returnsCustomStrategy() {
        // Given
        IKeyManagementStrategy customStrategy = mock(IKeyManagementStrategy.class);
        strategyMap.put("custom", customStrategy);
        KeyManagementStrategyFactory customFactory = new KeyManagementStrategyFactory(strategyMap);

        // When
        IKeyManagementStrategy result = customFactory.getStrategy("custom");

        // Then
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(customStrategy);
    }

    /**
     * Tests that factory returns same instance on multiple calls.
     */
    @Test
    @DisplayName("getStrategy() returns same instance on multiple calls")
    void getStrategy_multipleCalls_returnsSameInstance() {
        // When
        IKeyManagementStrategy result1 = factory.getStrategy("key");
        IKeyManagementStrategy result2 = factory.getStrategy("key");

        // Then
        assertThat(result1).isSameAs(result2);
        assertThat(result1).isSameAs(keyStrategy);
    }
}

