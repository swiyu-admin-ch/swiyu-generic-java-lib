package ch.admin.bj.swiyu.jwssignatureservice.config;

import ch.admin.bj.swiyu.jwssignatureservice.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.IKeyManagementStrategy;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.util.Map;

/**
 * Auto-configuration for KeyManagementStrategyFactory.
 * Registers all available IKeyManagementStrategy beans and provides the factory bean.
 */
@AutoConfiguration
@Import({
        ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategy.class,
        ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.PKCS11Strategy.class,
        ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.SecurosysStrategy.class
})
public class KeyManagementStrategyFactoryConfiguration {

    /**
     * Default constructor for KeyManagementStrategyFactoryConfiguration.
     * Required for frameworks and serialization.
     */
    public KeyManagementStrategyFactoryConfiguration() {
        // Default constructor
    }

    /**
     * Creates a KeyManagementStrategyFactory bean with all available strategies.
     *
     * @param strategyMap map of strategy bean names to strategy instances
     * @return a configured KeyManagementStrategyFactory
     */
    @Bean
    public KeyManagementStrategyFactory keyManagementStrategyFactory(Map<String, IKeyManagementStrategy> strategyMap) {
        return new KeyManagementStrategyFactory(strategyMap);
    }
}
