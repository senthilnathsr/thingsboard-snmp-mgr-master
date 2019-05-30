package org.thingsboard.server.transport.snmp.push;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.extern.slf4j.Slf4j;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.thingsboard.server.transport.snmp.util.SnmpUtility;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

@Slf4j
public class SnmpPushDaemon implements Callable<String> {

    private int sendRetries=2;
    private long rpcRequestTimeout=1000;
    private Map<String, OID> oidDottedMap = new HashMap<>();

    private Map<String, String> oidMap = new HashMap<>();

    private String message;

    public SnmpPushDaemon(final String message, final int sendRetries, final long rpcRequestTimeout) {
        this.message = message;
        this.sendRetries = sendRetries;
        this.rpcRequestTimeout = rpcRequestTimeout;
        loadData();
        loadOidMap();
    }

    public String call()  {
        String result = null;
        try {
            result = doSnmpPush(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private String doSnmpPush(final String msg) throws Exception {
        String result = "";
        log.info("SnmpPushDaemon:: SNMP GET - Received MSG={}",msg);
        JsonObject json = new JsonParser().parse(msg).getAsJsonObject();
        String methodStr = json.get("method").getAsString();
        String paramsStr = json.get("params").getAsString();
        JsonObject params = new JsonParser().parse(json.get("params").getAsString()).getAsJsonObject();
        String targetAddress = params.get("agentHost").getAsString();
        int port = params.get("agentPort").getAsInt();
        String trapOid = params.get("trapOid").getAsString();
        String methodName = params.get("methodName").getAsString();
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        // Create TransportMapping and Listen
        TransportMapping transport = new DefaultUdpTransportMapping();
        transport.listen();

        // Create Target Address object
        CommunityTarget comtarget = new CommunityTarget();
        comtarget.setCommunity(new OctetString("public"));
        comtarget.setVersion(SnmpConstants.version2c);
        comtarget.setAddress(new UdpAddress(targetAddress + "/" + port));
        comtarget.setRetries(sendRetries);
        comtarget.setTimeout(rpcRequestTimeout);

        // Create the PDU object
        PDU pdu = new PDU();
        if ((trapOid != null) && (trapOid.trim().length() > 0)) {
            pdu.add(new VariableBinding(new OID(trapOid), new OctetString(methodStr)));
            log.info("TrapOID if (" + trapOid + "), found for method: " + methodName);
        } else {
            pdu.add(new VariableBinding(new OID(getOid(oidMap, methodName)), new OctetString(methodStr)));
            log.info("TrapOID else (" + getOid(oidMap, methodName) + "), found for method: " + methodName);
        }
        pdu.setType(PDU.GET);
        pdu.setRequestID(new Integer32(SnmpUtility.nextRequestId()));

        // Create Snmp object for sending data to Agent
        Snmp snmp = new Snmp(transport);

        log.info("Sending Request to Agent...");
        ResponseEvent response = snmp.get(pdu, comtarget);

        // Process Agent Response
        if (response != null) {
            log.info("Got Response from Agent");
            PDU responsePDU = response.getResponse();

            if (responsePDU != null) {
                result = responsePDU.toString();
                log.info("Repsonse Received: " + result);
                int pduType = responsePDU.getType();
                System.out.println("Trap Type = " + pduType);
                System.out.println("Variable Bindings = " + responsePDU.getVariableBindings());

                int errorStatus = responsePDU.getErrorStatus();
                int errorIndex = responsePDU.getErrorIndex();
                String errorStatusText = responsePDU.getErrorStatusText();

                if (errorStatus == PDU.noError) {
                   log.info("Snmp Get Response={}", responsePDU.getVariableBindings());
                  //  JsonObject jsonObject = new JsonParser().parse(result).getAsJsonObject();

                } else {
                    log.warn("Error: Request Failed Error Status={}, Error Index={}, Error Status Text={}", errorStatus, errorIndex, errorStatusText);
                }
            } else {
                log.warn("Error: Response PDU is null");
            }
        } else {
            log.error("Error: Agent Timeout... ");
        }
        snmp.close();
        return result;
    }

    protected <K, V> K  getOid(Map<K, V> map, V value) {
        for (Map.Entry<K, V> entry : map.entrySet()) {
            if (value.equals(entry.getValue())) {
                return entry.getKey();
            }
        }
        return null;
    }

    protected void loadData() {

    }

//    public static void main(String[] args) {
    ////        String jsonStr = "{\"method\":\"cxSysGetUptime\",\"params\":\"{\\\"trapOid\\\": \\\"1.3.6.1.2.1.1.3.0\\\", \\\"requestId\\\":2881405, \\\"agentHost\\\": \\\"127.0.0.1\\\", \\\"agentPort\\\": \\\"9998\\\"}\",\"timeout\":500}";
////        String jsonStr = "{\"method\":\"cxSysGetUptime\",\"params\":\"{\\\"trapOid\\\": \\\"1.3.6.1.2.1.1.1.0\\\", \\\"requestId\\\":2881405, \\\"agentHost\\\": \\\"127.0.0.1\\\", \\\"agentPort\\\": \\\"9998\\\"}\",\"timeout\":500}";
////        String jsonStr = "{\"method\":\"cxSysGetUptime\",\"params\":\"{\\\"trapOid\\\": \\\"1.3.6.1.2.1.1.5.0\\\", \\\"requestId\\\":2881405, \\\"agentHost\\\": \\\"127.0.0.1\\\", \\\"agentPort\\\": \\\"9998\\\"}\",\"timeout\":500}";
//        String jsonStr = "{\"method\":\"cxSysGetUptime\",\"params\":\"{\\\"trapOid\\\": \\\"1.3.6.1.2.1.1.5.1.1.0\\\", \\\"requestId\\\":2881405, \\\"agentHost\\\": \\\"127.0.0.1\\\", \\\"agentPort\\\": \\\"9998\\\"}\",\"timeout\":500}";
//        JsonObject json = new JsonParser().parse(jsonStr).getAsJsonObject();
//        String paramsStr = json.get("params").getAsString();
//        JsonObject params = new JsonParser().parse(json.get("params").getAsString()).getAsJsonObject();
//        String targetAddress = params.get("agentHost").getAsString();
//        int port = params.get("agentPort").getAsInt();
//        System.out.println(port);
//
//        System.out.println(SnmpConstants.sysName.toDottedString());
//        SnmpPushDaemon daemon = new SnmpPushDaemon(jsonStr, 2, 1000);
//        daemon.call();
//    }

    public void loadOidMap() {
        oidMap.put(SnmpConstants.usmNoAuthProtocol.toDottedString(),"usmNoAuthProtocol");
        oidMap.put(SnmpConstants.usmHMACMD5AuthProtocol.toDottedString(), "usmHMACMD5AuthProtocol");
        oidMap.put(SnmpConstants.usmHMACSHAAuthProtocol.toDottedString(), "usmHMACSHAAuthProtocol");
        oidMap.put(SnmpConstants.usmNoPrivProtocol.toDottedString(), "usmNoPrivProtocol");
        oidMap.put(SnmpConstants.usmDESPrivProtocol.toDottedString(), "usmDESPrivProtocol");
        oidMap.put(SnmpConstants.usm3DESEDEPrivProtocol.toDottedString(), "usm3DESEDEPrivProtocol");
        oidMap.put(SnmpConstants.usmAesCfb128Protocol.toDottedString(), "usmAesCfb128Protocol");
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb192Protocol.toDottedString(), "oosnmpUsmAesCfb192Protocol");
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb256Protocol.toDottedString(), "oosnmpUsmAesCfb256Protocol");
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb192ProtocolWith3DESKeyExtension.toDottedString(), "oosnmpUsmAesCfb192ProtocolWith3DESKeyExtension");
        oidMap.put(SnmpConstants.oosnmpUsmAesCfb256ProtocolWith3DESKeyExtension.toDottedString(), "oosnmpUsmAesCfb256ProtocolWith3DESKeyExtension");
        oidMap.put(SnmpConstants.usmStatsUnsupportedSecLevels.toDottedString(), "usmStatsUnsupportedSecLevels");
        oidMap.put(SnmpConstants.usmStatsNotInTimeWindows.toDottedString(), "usmStatsNotInTimeWindows");
        oidMap.put(SnmpConstants.usmStatsUnknownUserNames.toDottedString(), "usmStatsUnknownUserNames");
        oidMap.put(SnmpConstants.usmStatsUnknownEngineIDs.toDottedString(), "usmStatsUnknownEngineIDs");
        oidMap.put(SnmpConstants.usmStatsWrongDigests.toDottedString(), "usmStatsWrongDigests");
        oidMap.put(SnmpConstants.usmStatsDecryptionErrors.toDottedString(), "usmStatsDecryptionErrors");
        oidMap.put(SnmpConstants.snmpEngineID.toDottedString(), "snmpEngineID");
        oidMap.put(SnmpConstants.snmpUnknownSecurityModels.toDottedString(), "snmpUnknownSecurityModels");
        oidMap.put(SnmpConstants.snmpInvalidMsgs.toDottedString(), "snmpInvalidMsgs");
        oidMap.put(SnmpConstants.snmpUnknownPDUHandlers.toDottedString(), "snmpUnknownPDUHandlers");
        oidMap.put(SnmpConstants.snmpInPkts.toDottedString(), "snmpInPkts");
        oidMap.put(SnmpConstants.snmpInBadVersions.toDottedString(), "snmpInBadVersions");
        oidMap.put(SnmpConstants.snmpInBadCommunityNames.toDottedString(), "snmpInBadCommunityNames");
        oidMap.put(SnmpConstants.snmpInBadCommunityUses.toDottedString(), "snmpInBadCommunityUses");
        oidMap.put(SnmpConstants.snmpInASNParseErrs.toDottedString(), "snmpInASNParseErrs");
        oidMap.put(SnmpConstants.snmpSilentDrops.toDottedString(), "snmpSilentDrops");
        oidMap.put(SnmpConstants.snmpProxyDrops.toDottedString(), "snmpProxyDrops");
        oidMap.put(SnmpConstants.snmpTrapOID.toDottedString(), "snmpTrapOID");
        oidMap.put(SnmpConstants.snmpTrapEnterprise.toDottedString(), "snmpTrapEnterprise");
        oidMap.put(SnmpConstants.snmpTraps.toDottedString(), "snmpTraps");
        oidMap.put(SnmpConstants.coldStart.toDottedString(), "coldStart");
        oidMap.put(SnmpConstants.warmStart.toDottedString(), "warmStart");
        oidMap.put(SnmpConstants.authenticationFailure.toDottedString(), "authenticationFailure");
        oidMap.put(SnmpConstants.linkDown.toDottedString(), "linkDown");
        oidMap.put(SnmpConstants.linkUp.toDottedString(), "linkUp");
        oidMap.put(SnmpConstants.sysDescr.toDottedString(), "sysDescr");
        oidMap.put(SnmpConstants.sysObjectID.toDottedString(), "sysObjectID");
        oidMap.put(SnmpConstants.sysUpTime.toDottedString(), "sysUpTime");
        oidMap.put(SnmpConstants.sysContact.toDottedString(), "sysContact");
        oidMap.put(SnmpConstants.sysName.toDottedString(), "sysName");
        oidMap.put(SnmpConstants.sysLocation.toDottedString(), "sysLocation");
        oidMap.put(SnmpConstants.sysServices.toDottedString(), "sysServices");
        oidMap.put(SnmpConstants.sysOREntry.toDottedString(), "sysOREntry");
        oidMap.put(SnmpConstants.system.toDottedString(), "system");
        oidMap.put(SnmpConstants.snmpUnavailableContexts.toDottedString(), "snmpUnavailableContexts");
        oidMap.put(SnmpConstants.snmpUnknownContexts.toDottedString(), "snmpUnknownContexts");
        oidMap.put(SnmpConstants.snmpTrapAddress.toDottedString(), "snmpTrapAddress");
        oidMap.put(SnmpConstants.snmpTrapCommunity.toDottedString(), "snmpTrapCommunity");
        oidMap.put(SnmpConstants.zeroDotZero.toDottedString(), "zeroDotZero");
        oidMap.put(SnmpConstants.snmpTsmInvalidCaches.toDottedString(), "snmpTsmInvalidCaches");
        oidMap.put(SnmpConstants.snmpTsmInadequateSecurityLevels.toDottedString(), "snmpTsmInadequateSecurityLevels");
        oidMap.put(SnmpConstants.snmpTsmUnknownPrefixes.toDottedString(), "snmpTsmUnknownPrefixes");
        oidMap.put(SnmpConstants.snmpTsmInvalidPrefixes.toDottedString(), "snmpTsmInvalidPrefixes");
        oidMap.put(SnmpConstants.snmpTsmConfigurationUsePrefix.toDottedString(), "snmpTsmConfigurationUsePrefix");
        oidMap.put(SnmpConstants.snmpTlstmSessionOpens.toDottedString(), "snmpTlstmSessionOpens");
        oidMap.put(SnmpConstants.snmpTlstmSessionClientCloses.toDottedString(), "snmpTlstmSessionClientCloses");
        oidMap.put(SnmpConstants.snmpTlstmSessionOpenErrors.toDottedString(), "snmpTlstmSessionOpenErrors");
        oidMap.put(SnmpConstants.snmpTlstmSessionAccepts.toDottedString(), "snmpTlstmSessionAccepts");
        oidMap.put(SnmpConstants.snmpTlstmSessionServerCloses.toDottedString(), "snmpTlstmSessionServerCloses");
        oidMap.put(SnmpConstants.snmpTlstmSessionNoSessions.toDottedString(), "snmpTlstmSessionNoSessions");
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidClientCertificates.toDottedString(), "snmpTlstmSessionInvalidClientCertificates");
        oidMap.put(SnmpConstants.snmpTlstmSessionUnknownServerCertificate.toDottedString(), "snmpTlstmSessionUnknownServerCertificate");
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidServerCertificates.toDottedString(), "snmpTlstmSessionInvalidServerCertificates");
        oidMap.put(SnmpConstants.snmpTlstmSessionInvalidCaches.toDottedString(), "snmpTlstmSessionInvalidCaches");
        oidMap.put(SnmpConstants.snmpSshtmSessionOpens.toDottedString(), "snmpSshtmSessionOpens");
        oidMap.put(SnmpConstants.snmpSshtmSessionCloses.toDottedString(), "snmpSshtmSessionCloses");
        oidMap.put(SnmpConstants.snmpSshtmSessionOpenErrors.toDottedString(), "snmpSshtmSessionOpenErrors");
        oidMap.put(SnmpConstants.snmpSshtmSessionUserAuthFailures.toDottedString(), "snmpSshtmSessionUserAuthFailures");
        oidMap.put(SnmpConstants.snmpSshtmSessionNoChannels.toDottedString(), "snmpSshtmSessionNoChannels");
        oidMap.put(SnmpConstants.snmpSshtmSessionNoSubsystems.toDottedString(), "snmpSshtmSessionNoSubsystems");
        oidMap.put(SnmpConstants.snmpSshtmSessionNoSessions.toDottedString(), "snmpSshtmSessionNoSessions");
        oidMap.put(SnmpConstants.snmpSshtmSessionInvalidCaches.toDottedString(), "snmpSshtmSessionInvalidCaches");
        oidMap.put(SnmpConstants.snmp4jStatsRequestTimeouts.toDottedString(), "snmp4jStatsRequestTimeouts");
        oidMap.put(SnmpConstants.snmp4jStatsRequestRetries.toDottedString(), "snmp4jStatsRequestRetries");
        oidMap.put(SnmpConstants.snmp4jStatsRequestWaitTime.toDottedString(), "snmp4jStatsRequestWaitTime");
        oidMap.put(SnmpConstants.snmp4jStatsRequestRuntime.toDottedString(), "snmp4jStatsRequestRuntime");
        oidMap.put(SnmpConstants.snmp4jStatsReqTableTimeouts.toDottedString(), "snmp4jStatsReqTableTimeouts");
        oidMap.put(SnmpConstants.snmp4jStatsReqTableRetries.toDottedString(), "snmp4jStatsReqTableRetries");
        oidMap.put(SnmpConstants.snmp4jStatsReqTableWaitTime.toDottedString(), "snmp4jStatsReqTableWaitTime");
        oidMap.put(SnmpConstants.snmp4jStatsReqTableRuntime.toDottedString(), "snmp4jStatsReqTableRuntime");
        oidMap.put(SnmpConstants.snmp4jStatsResponseTimeouts.toDottedString(), "snmp4jStatsResponseTimeouts");
        oidMap.put(SnmpConstants.snmp4jStatsResponseIgnoredRetries.toDottedString(), "snmp4jStatsResponseIgnoredRetries");
        oidMap.put(SnmpConstants.snmp4jStatsResponseProcessTime.toDottedString(), "snmp4jStatsResponseProcessTime");
        oidMap.put(SnmpConstants.snmpSetSerialNo.toDottedString(), "snmpSetSerialNo");
    }
}
