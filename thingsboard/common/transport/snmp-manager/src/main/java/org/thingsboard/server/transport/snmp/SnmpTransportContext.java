package org.thingsboard.server.transport.snmp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.transport.TransportContext;

@Slf4j
@ConditionalOnExpression("'${transport.type:null}'=='null' || ('${transport.type}'=='local' && '${transport.snmp.enabled}'=='true')")
@Component
public class SnmpTransportContext extends TransportContext {

}