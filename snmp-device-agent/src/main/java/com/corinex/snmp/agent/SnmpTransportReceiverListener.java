package com.corinex.snmp.agent;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.snmp4j.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.*;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.*;
import org.snmp4j.tools.console.SnmpRequest;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Slf4j
@Component
public class SnmpTransportReceiverListener implements CommandResponder {

    @Getter
    @Value("${snmp.agent.agentHost}")
    private String agentHost;

    @Getter
    @Value("${snmp.agent.agentPort}")
    private int agentPort;

    private Map<String, OID> oidMap = new HashMap<>();

    private static Random random = new Random();

    public SnmpTransportReceiverListener() {}

    @PostConstruct
    public void init() {
        loadOidMap();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationEvent(ApplicationReadyEvent applicationReadyEvent) {
        log.info("SnmpTransportReceiver:: Received application ready event. Starting polling for events.");
        startSnmpListener();
    }

    public void startSnmpListener() {
        try {
            log.info("Initializing SNMP Transport Receiver... ");
            this.listen(new UdpAddress(agentHost + "/" + agentPort));
            log.info("Initialized SNMP Transport Receiver... ");
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Error in Listening for Trap");
            System.err.println("Exception Message = " + e.getMessage());
        }
    }

    /**
     * This method will listen for traps and response pdu's from SNMP agent.
     */
    protected synchronized void listen(TransportIpAddress address) throws IOException {
        AbstractTransportMapping transport;
        if (address instanceof TcpAddress) {
            transport = new DefaultTcpTransportMapping((TcpAddress) address);
        } else {
            transport = new DefaultUdpTransportMapping((UdpAddress) address);
        }

        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
        MessageDispatcher mtDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

        // add message processing models
        mtDispatcher.addMessageProcessingModel(new MPv1());
        mtDispatcher.addMessageProcessingModel(new MPv2c());

        // add all security protocols
        SecurityProtocols.getInstance().addDefaultProtocols();
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        //Create Target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity( new OctetString("public"));

        Snmp snmp = new Snmp(mtDispatcher, transport);
        snmp.addCommandResponder(this);

        transport.listen();
        System.out.println("Listening on " + address);

        try {
            this.wait();
        } catch (InterruptedException ex) {
            log.warn("startSnmpListener:: interrupted... now closing...");
            if (snmp!=null) {snmp.close();};
        }
    }

    /**
     * This method will be called whenever a pdu is received on the given port specified in the listen() method
     */
    public synchronized void processPdu(CommandResponderEvent cmdRespEvent) {
        System.out.println("Received PDU...");
        PDU pdu = cmdRespEvent.getPDU();
        if (pdu != null) {
            int pduType = pdu.getType();
            if ((pduType == PDU.GET) || (pduType == PDU.NOTIFICATION)) {
                //
            } else {
                System.out.println("Other snmp request type...");
            }
            System.out.println("Trap Type Received = " + pduType);
            System.out.println("Variable Bindings = " + pdu.getVariableBindings());
            VariableBinding variableBinding = (VariableBinding) pdu.getVariableBindings().get(0);
            OID oid = variableBinding.getOid();
            Variable payloadVar = variableBinding.getVariable();
            String payload = payloadVar.toString();

            try {
                pdu.setErrorIndex(0);
                pdu.setErrorStatus(0);
                pdu.setType(PDU.RESPONSE);
                if (oidMap.containsKey(oid.toDottedString())) {
                    if (SnmpConstants.sysUpTime.toDottedString().equalsIgnoreCase(oid.toDottedString())) {
                        pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(
                                new UnsignedInteger32(System.currentTimeMillis() / 1000)
                                        .getValue())));
                    } else if (SnmpConstants.sysDescr.toDottedString().equalsIgnoreCase(oid.toDottedString())){
                        pdu.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("BPL 100 Network Router")));
                    } else {
                        pdu.add(new VariableBinding(oidMap.get(oid.toDottedString()), new OctetString("Echo Response")));
                    }
                } else {
                    pdu.add(new VariableBinding(oid, new OctetString("Unknown Device OID...")));
                }
                System.out.println("PDU =" + cmdRespEvent.getPDU());
                StatusInformation statusInformation = new StatusInformation();
                StateReference ref = cmdRespEvent.getStateReference();
                cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
                        cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
                        pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
            } catch (MessageException ex) {
                System.err.println("Error while sending response: " + ex.getMessage());
                LogFactory.getLogger(SnmpRequest.class).error(ex);
            }
        }
    }

    @PreDestroy
    public void destroy() {
        Thread.currentThread().interrupt();
    }

    public void loadOidMap() {
        oidMap.put(SnmpConstants.usmNoAuthProtocol.toDottedString(),SnmpConstants.usmNoAuthProtocol);
        oidMap.put(SnmpConstants.usmHMACMD5AuthProtocol.toDottedString(),SnmpConstants.usmHMACMD5AuthProtocol);
        oidMap.put(SnmpConstants.usmHMACSHAAuthProtocol.toDottedString(),SnmpConstants.usmHMACSHAAuthProtocol);
        oidMap.put(SnmpConstants.usmNoPrivProtocol.toDottedString(),SnmpConstants.usmNoPrivProtocol);
        oidMap.put(SnmpConstants.usmDESPrivProtocol.toDottedString(),SnmpConstants.usmDESPrivProtocol);
        oidMap.put(SnmpConstants.usm3DESEDEPrivProtocol.toDottedString(),SnmpConstants.usm3DESEDEPrivProtocol);
        oidMap.put(SnmpConstants.usmAesCfb128Protocol.toDottedString(),SnmpConstants.usmAesCfb128Protocol);
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb192Protocol.toDottedString(),SnmpConstants.oosnmpUsmAesCfb192Protocol);
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb256Protocol.toDottedString(),SnmpConstants.oosnmpUsmAesCfb256Protocol);
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb192ProtocolWith3DESKeyExtension.toDottedString(),SnmpConstants.oosnmpUsmAesCfb192ProtocolWith3DESKeyExtension);
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb256ProtocolWith3DESKeyExtension.toDottedString(),SnmpConstants.oosnmpUsmAesCfb256ProtocolWith3DESKeyExtension);
        oidMap.put(SnmpConstants.usmStatsUnsupportedSecLevels.toDottedString(),SnmpConstants.usmStatsUnsupportedSecLevels);
        oidMap.put(SnmpConstants.usmStatsNotInTimeWindows.toDottedString(),SnmpConstants.usmStatsNotInTimeWindows);
        oidMap.put(SnmpConstants.usmStatsUnknownUserNames.toDottedString(),SnmpConstants.usmStatsUnknownUserNames);
        oidMap.put(SnmpConstants.usmStatsUnknownEngineIDs.toDottedString(),SnmpConstants.usmStatsUnknownEngineIDs);
        oidMap.put(SnmpConstants.usmStatsWrongDigests.toDottedString(),SnmpConstants.usmStatsWrongDigests);
        oidMap.put(SnmpConstants.usmStatsDecryptionErrors.toDottedString(),SnmpConstants.usmStatsDecryptionErrors);
        oidMap.put(SnmpConstants.snmpEngineID.toDottedString(),SnmpConstants.snmpEngineID);
        oidMap.put(SnmpConstants.snmpUnknownSecurityModels.toDottedString(),SnmpConstants.snmpUnknownSecurityModels);
        oidMap.put(SnmpConstants.snmpInvalidMsgs.toDottedString(),SnmpConstants.snmpInvalidMsgs);
        oidMap.put(SnmpConstants.snmpUnknownPDUHandlers.toDottedString(),SnmpConstants.snmpUnknownPDUHandlers);
        oidMap.put(SnmpConstants.snmpInPkts.toDottedString(),SnmpConstants.snmpInPkts);
        oidMap.put(SnmpConstants.snmpInBadVersions.toDottedString(),SnmpConstants.snmpInBadVersions);
        oidMap.put(SnmpConstants.snmpInBadCommunityNames.toDottedString(),SnmpConstants.snmpInBadCommunityNames);
        oidMap.put(SnmpConstants.snmpInBadCommunityUses.toDottedString(),SnmpConstants.snmpInBadCommunityUses);
        oidMap.put(SnmpConstants.snmpInASNParseErrs.toDottedString(),SnmpConstants.snmpInASNParseErrs);
        oidMap.put(SnmpConstants.snmpSilentDrops.toDottedString(),SnmpConstants.snmpSilentDrops);
        oidMap.put(SnmpConstants.snmpProxyDrops.toDottedString(),SnmpConstants.snmpProxyDrops);
        oidMap.put(SnmpConstants.snmpTrapOID.toDottedString(),SnmpConstants.snmpTrapOID);
        oidMap.put(SnmpConstants.snmpTrapEnterprise.toDottedString(),SnmpConstants.snmpTrapEnterprise);
        oidMap.put(SnmpConstants.snmpTraps.toDottedString(),SnmpConstants.snmpTraps);
        oidMap.put(SnmpConstants.coldStart.toDottedString(),SnmpConstants.coldStart);
        oidMap.put(SnmpConstants.warmStart.toDottedString(),SnmpConstants.warmStart);
        oidMap.put(SnmpConstants.authenticationFailure.toDottedString(),SnmpConstants.authenticationFailure);
        oidMap.put(SnmpConstants.linkDown.toDottedString(),SnmpConstants.linkDown);
        oidMap.put(SnmpConstants.linkUp.toDottedString(),SnmpConstants.linkUp);
        oidMap.put(SnmpConstants.sysDescr.toDottedString(),SnmpConstants.sysDescr);
        oidMap.put(SnmpConstants.sysObjectID.toDottedString(),SnmpConstants.sysObjectID);
        oidMap.put(SnmpConstants.sysUpTime.toDottedString(),SnmpConstants.sysUpTime);
        oidMap.put(SnmpConstants.sysContact.toDottedString(),SnmpConstants.sysContact);
        oidMap.put(SnmpConstants.sysName.toDottedString(),SnmpConstants.sysName);
        oidMap.put(SnmpConstants.sysLocation.toDottedString(),SnmpConstants.sysLocation);
        oidMap.put(SnmpConstants.sysServices.toDottedString(),SnmpConstants.sysServices);
        oidMap.put(SnmpConstants.sysOREntry.toDottedString(),SnmpConstants.sysOREntry);
        oidMap.put(SnmpConstants.system.toDottedString(),SnmpConstants.system);
        oidMap.put(SnmpConstants.snmpUnavailableContexts.toDottedString(),SnmpConstants.snmpUnavailableContexts);
        oidMap.put(SnmpConstants.snmpUnknownContexts.toDottedString(),SnmpConstants.snmpUnknownContexts);
        oidMap.put(SnmpConstants.snmpTrapAddress.toDottedString(),SnmpConstants.snmpTrapAddress);
        oidMap.put(SnmpConstants.snmpTrapCommunity.toDottedString(),SnmpConstants.snmpTrapCommunity);
        oidMap.put(SnmpConstants.zeroDotZero.toDottedString(),SnmpConstants.zeroDotZero);
        oidMap.put(SnmpConstants.snmpTsmInvalidCaches.toDottedString(),SnmpConstants.snmpTsmInvalidCaches);
        oidMap.put(SnmpConstants.snmpTsmInadequateSecurityLevels.toDottedString(),SnmpConstants.snmpTsmInadequateSecurityLevels);
        oidMap.put(SnmpConstants.snmpTsmUnknownPrefixes.toDottedString(),SnmpConstants.snmpTsmUnknownPrefixes);
        oidMap.put(SnmpConstants.snmpTsmInvalidPrefixes.toDottedString(),SnmpConstants.snmpTsmInvalidPrefixes);
        oidMap.put(SnmpConstants.snmpTsmConfigurationUsePrefix.toDottedString(),SnmpConstants.snmpTsmConfigurationUsePrefix);
        oidMap.put(SnmpConstants.snmpTlstmSessionOpens.toDottedString(),SnmpConstants.snmpTlstmSessionOpens);
        oidMap.put(SnmpConstants.snmpTlstmSessionClientCloses.toDottedString(),SnmpConstants.snmpTlstmSessionClientCloses);
        oidMap.put(SnmpConstants.snmpTlstmSessionOpenErrors.toDottedString(),SnmpConstants.snmpTlstmSessionOpenErrors);
        oidMap.put(SnmpConstants.snmpTlstmSessionAccepts.toDottedString(),SnmpConstants.snmpTlstmSessionAccepts);
        oidMap.put(SnmpConstants.snmpTlstmSessionServerCloses.toDottedString(),SnmpConstants.snmpTlstmSessionServerCloses);
        oidMap.put(SnmpConstants.snmpTlstmSessionNoSessions.toDottedString(),SnmpConstants.snmpTlstmSessionNoSessions);
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidClientCertificates.toDottedString(),SnmpConstants.snmpTlstmSessionInvalidClientCertificates);
        oidMap.put(SnmpConstants.snmpTlstmSessionUnknownServerCertificate.toDottedString(),SnmpConstants.snmpTlstmSessionUnknownServerCertificate);
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidServerCertificates.toDottedString(),SnmpConstants.snmpTlstmSessionInvalidServerCertificates);
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidCaches.toDottedString(),SnmpConstants.snmpTlstmSessionInvalidCaches);
        oidMap.put(SnmpConstants.snmpSshtmSessionOpens.toDottedString(),SnmpConstants.snmpSshtmSessionOpens);
        oidMap.put(SnmpConstants.snmpSshtmSessionCloses.toDottedString(),SnmpConstants.snmpSshtmSessionCloses);
        oidMap.put(SnmpConstants.snmpSshtmSessionOpenErrors.toDottedString(),SnmpConstants.snmpSshtmSessionOpenErrors);
        oidMap.put(SnmpConstants.snmpSshtmSessionUserAuthFailures.toDottedString(),SnmpConstants.snmpSshtmSessionUserAuthFailures);
        oidMap.put(SnmpConstants.snmpSshtmSessionNoChannels.toDottedString(),SnmpConstants.snmpSshtmSessionNoChannels);
        oidMap.put(SnmpConstants.snmpSshtmSessionNoSubsystems.toDottedString(),SnmpConstants.snmpSshtmSessionNoSubsystems);
        oidMap.put(SnmpConstants.snmpSshtmSessionNoSessions.toDottedString(),SnmpConstants.snmpSshtmSessionNoSessions);
        oidMap.put(SnmpConstants.snmpSshtmSessionInvalidCaches.toDottedString(),SnmpConstants.snmpSshtmSessionInvalidCaches);
        oidMap.put(SnmpConstants.snmp4jStatsRequestTimeouts.toDottedString(),SnmpConstants.snmp4jStatsRequestTimeouts);
        oidMap.put(SnmpConstants.snmp4jStatsRequestRetries.toDottedString(),SnmpConstants.snmp4jStatsRequestRetries);
        oidMap.put(SnmpConstants.snmp4jStatsRequestWaitTime.toDottedString(),SnmpConstants.snmp4jStatsRequestWaitTime);
        oidMap.put(SnmpConstants.snmp4jStatsRequestRuntime.toDottedString(),SnmpConstants.snmp4jStatsRequestRuntime);
        oidMap.put(SnmpConstants.snmp4jStatsReqTableTimeouts.toDottedString(),SnmpConstants.snmp4jStatsReqTableTimeouts);
        oidMap.put(SnmpConstants.snmp4jStatsReqTableRetries.toDottedString(),SnmpConstants.snmp4jStatsReqTableRetries);
        oidMap.put(SnmpConstants.snmp4jStatsReqTableWaitTime.toDottedString(),SnmpConstants.snmp4jStatsReqTableWaitTime);
        oidMap.put(SnmpConstants.snmp4jStatsReqTableRuntime.toDottedString(),SnmpConstants.snmp4jStatsReqTableRuntime);
        oidMap.put(SnmpConstants.snmp4jStatsResponseTimeouts.toDottedString(),SnmpConstants.snmp4jStatsResponseTimeouts);
        oidMap.put(SnmpConstants.snmp4jStatsResponseIgnoredRetries.toDottedString(),SnmpConstants.snmp4jStatsResponseIgnoredRetries);
        oidMap.put(SnmpConstants.snmp4jStatsResponseProcessTime.toDottedString(),SnmpConstants.snmp4jStatsResponseProcessTime);
        oidMap.put(SnmpConstants.snmpSetSerialNo.toDottedString(),SnmpConstants.snmpSetSerialNo);
    }
}
