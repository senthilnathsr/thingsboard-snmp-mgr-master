package org.thingsboard.server.transport.snmp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Slf4j
@Component
public class SnmpTransportReceiver {

    @Autowired
    private SnmpTransportContext snmpTransportContext;

    @Autowired
    private SnmpTransportReceiverListener transportReceiverListener;

    @PostConstruct
    public void init() {
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationEvent(ApplicationReadyEvent applicationReadyEvent) {
        log.info("SnmpTransportReceiver:: Received application ready event. Starting polling for events.");
        transportReceiverListener.startSnmpListener();
    }

    @PreDestroy
    public void destroy() {
        transportReceiverListener.interrupt();
    }
}
