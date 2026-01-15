package com.venus.encrypt;

import com.alibaba.nacos.plugin.environment.spi.CustomEnvironmentPluginService;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

@SuppressWarnings("PMD.ServiceOrDaoClassShouldEndWithImplRule")
public class NacosDbEncryptPluginService implements CustomEnvironmentPluginService {
    private static final Logger logger = Logger.getLogger(NacosDbEncryptPluginService.class.getName());

    private static final String DB_PWD_KEY = "db.password.0";

    @Override
    public Map<String, Object> customValue(Map<String, Object> property) {
        String pwd = (String) property.get(DB_PWD_KEY);
        logger.info("venus plugin Original pwd:"+pwd);
        String decrypt = VenusAesUtil.decrypt(pwd);
        logger.info("venus plugin Encrypt pwd:"+decrypt);
        property.put(DB_PWD_KEY, decrypt);
        return property;
    }

    @Override
    public Set<String> propertyKey() {
        Set<String> propertyKey = new HashSet<>();
        propertyKey.add(DB_PWD_KEY);
        return propertyKey;
    }

    @Override
    public Integer order() {
        return 1;
    }

    @Override
    public String pluginName() {
        return "NacosDbEncryptPluginService";
    }
}
