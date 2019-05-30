package com.corinex.snmp.agent;



/*
 * The <code>org.thingsboard.server.transport.snmp.SnmpTransportSender</code> class extends the SNMP4J BaseAgent
 * class to provide a mock SNMP agent for SNMP-based OpenNMS tests.
 * Large chunks of code were lifted from the org.snmp4j.agent.test.TestAgent
 * class.
 *
 * @author Jeff Gehlbach
 * @version 1.0
 */

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Getter;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * <p>org.thingsboard.server.transport.snmp.SnmpTransportSender class.</p>
 *
 * @author ranger
 * @version $Id: $
 */
@Slf4j
@Component
@EnableScheduling
public class SnmpTransportSender {

    @Getter
    @Value("${snmp.server.targetAddress}")
    private String targetAddress;

    @Getter
    @Value("${snmp.server.targetPort}")
    private int targetPort;

    @Getter
    @Value("${snmp.server.sendTimeout}")
    private long sendTimeout;

    @Getter
    @Value("${snmp.server.sendRetries}")
    private int sendRetries;

    @Getter
    @Value("${snmp.agent.community}")
    private String community  = "public";

    @Getter
    @Value("${snmp.agent.trapOid}")
    private String trapOid = ".1.3.6.1.2.1.1.6";

    @Getter
    @Value("${snmp.agent.agentHost}")
    private String agentHost;

    @Getter
    @Value("${snmp.agent.agentPort}")
    private int agentPort;


    //  Sending Trap for sysLocation of RFC1213
//    public static final String trapOid = ".1.3.6.1.2.1.1.6";
//    public static final String ipAddress = "127.0.0.1";
//    public static final int port  = 9999;

    private final long currTime = System.currentTimeMillis();

    private static final String SYSUPTIME_TRAP_TEMPLATE = "{\n" +
            "  \"deviceToken\": \"A1_TEST_TOKEN\",\n" +
            "  \"method\": \"cxSysUptime\",\n" +
            "  \"params\": {\n" +
            "    \"sysUpTime\": 575342,\n" +
            "    \"agentHost\": \"127.0.0.1\",\n" +
            "    \"agentPort\": \"9988\"\n" +
            "  }\n" +
            "}";

    private static final String ATTRIBUTES_NOTIFICATION_TEMPLATE = "{\n" +
            "  \"deviceToken\": \"A1_TEST_TOKEN\",\n" +
            "  \"method\": \"cxSysAttributes\",\n" +
            "  \"params\": {\n" +
            "    \"upSpeed\": 0,\n" +
            "    \"downSpeed\": 0,\n" +
            "    \"agentHost\": \"127.0.0.1\",\n" +
            "    \"agentPort\": \"9988\"\n" +
            "  }\n" +
            "}";

    private JsonObject uptimeJsonObject = new JsonObject();
    private JsonObject attributesJsonObject = new JsonObject();

    @PostConstruct
    public void init() {
        uptimeJsonObject = new JsonParser().parse(SYSUPTIME_TRAP_TEMPLATE).getAsJsonObject();
        attributesJsonObject = new JsonParser().parse(ATTRIBUTES_NOTIFICATION_TEMPLATE).getAsJsonObject();
    }

    @Scheduled(fixedRateString="${snmp.agent.scheduled.trapSendRate}", initialDelay=2000)
    public void sendSnmpTrapNotification() {
        Snmp snmp = null;
        try {
            //Create Transport Mapping
            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();

            //Create Target
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(SnmpConstants.version2c);
            comtarget.setAddress(new UdpAddress(targetAddress + "/" + targetPort));
            comtarget.setRetries(sendRetries);
            comtarget.setTimeout(sendTimeout);

            //Create PDU for V2
            PDU pdu = new PDU();

            // need to specify the system up time
            pdu.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString(sysUptime())));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(trapOid)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(agentHost)));

            // variable binding for Enterprise Specific objects, Severity (should be defined in MIB file)
            pdu.add(new VariableBinding(new OID(trapOid), new OctetString("Major")));
            pdu.setType(PDU.NOTIFICATION);

            SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

            // Send the PDU
            snmp = new Snmp(transport);
            log.info("Sending V2 Trap to {} on Port {}", targetAddress, targetPort);
            snmp.send(pdu, comtarget);

        } catch (Exception e) {
            log.error("Error in Sending V2 Trap to {}:{}", targetAddress, targetPort, e);
        } finally {
           if(snmp!=null) {
               try {
                   snmp.close();
               } catch (Exception e) {
                    e.printStackTrace();
               }
           }
        }
    }

    @Scheduled(fixedRateString="${snmp.agent.scheduled.attrsSendRate}", initialDelay=1000)
    public void sendSnmpAttributes() {
        Snmp snmp = null;
        try {
            //Create Transport Mapping
            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();

            //Create Target
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(SnmpConstants.version2c);
            comtarget.setAddress(new UdpAddress(targetAddress + "/" + targetPort));
            comtarget.setRetries(sendRetries);
            comtarget.setTimeout(sendTimeout);

            //Create PDU for V2
            PDU pdu = new PDU();

            // need to specify the system up time
            pdu.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString(sysAttributes())));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(trapOid)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(agentHost)));

            // variable binding for Enterprise Specific objects, Severity (should be defined in MIB file)
            pdu.add(new VariableBinding(new OID(trapOid), new OctetString("Major")));
            pdu.setType(PDU.NOTIFICATION);
//            pdu.setType(PDU.GET);

            //Send the PDU
            snmp = new Snmp(transport);
            log.info("Sending V2 Attributes to {} on Port {}", targetAddress, targetPort);
            snmp.send(pdu, comtarget);

        } catch (Exception e) {
            log.error("Error in Sending V2 Attributes to {}:{}", targetAddress, targetPort, e);
        } finally {
            if(snmp!=null) {
                try {
                    snmp.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    protected String sysUptime() {
        JsonObject params = uptimeJsonObject.get("params").getAsJsonObject();
        params.addProperty("sysUpTime", System.currentTimeMillis() - currTime);
        String json = uptimeJsonObject.toString();
        System.out.println("json = " + json);

        System.out.println(uptimeJsonObject.get("deviceToken").getAsString());
        return json;
    }

    protected String sysAttributes() {
        JsonObject params = attributesJsonObject.get("params").getAsJsonObject();
        params.addProperty("upSpeed", genRandomNumInRange());
        params.addProperty("downSpeed", genRandomNumInRange());
        String json = attributesJsonObject.toString();
        System.out.println("json = " + json);

        System.out.println(attributesJsonObject.get("deviceToken").getAsString());
        return json;
    }

    public static void main(String[] args) {
        SnmpTransportSender sender = new SnmpTransportSender();
        sender.init();
        sender.sendSnmpTrapNotification();
        sender.sendSnmpAttributes();
    }

    private int genRandomNumInRange() {
        return org.apache.commons.lang3.RandomUtils.nextInt(10000, 100000);
    }
}