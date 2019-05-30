package org.thingsboard.server.transport.snmp.push;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class SnmpPushManager {

    @Getter
    @Value("${transport.snmp.push.poolSize}")
    private int pushPoolSize;

    @Getter
    @Value("${transport.snmp.push.rpcTimeout}")
    private long rpcRequestTimeout;

    @Getter
    @Value("${transport.snmp.push.sendRetries}")
    private int sendRetries;

    private ThreadPoolExecutor snmpThreadPoolExecutor;

    @PostConstruct
    public void init() {
        snmpThreadPoolExecutor =
                (ThreadPoolExecutor) Executors.newFixedThreadPool(pushPoolSize);
    }

    public void doSnmpPush(final String message) {
        if (snmpThreadPoolExecutor!=null) {
            snmpThreadPoolExecutor.submit(new SnmpPushDaemon(message, sendRetries, rpcRequestTimeout));
        }
    }

    @PreDestroy
    public void cleanup() {
        snmpThreadPoolExecutor.shutdown();
        boolean isCompleted = false;
        try {
            isCompleted = snmpThreadPoolExecutor.awaitTermination(500, TimeUnit.MILLISECONDS);
            if (!isCompleted) snmpThreadPoolExecutor.shutdownNow();
        } catch (InterruptedException e) {

        }
    }
}
