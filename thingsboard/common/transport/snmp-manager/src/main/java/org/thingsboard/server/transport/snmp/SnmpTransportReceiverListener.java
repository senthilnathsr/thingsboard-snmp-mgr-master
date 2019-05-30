package org.thingsboard.server.transport.snmp;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.transport.TransportContext;
import org.thingsboard.server.common.transport.TransportService;
import org.thingsboard.server.common.transport.TransportServiceCallback;
import org.thingsboard.server.common.transport.adaptor.JsonConverter;
import org.thingsboard.server.gen.transport.TransportProtos;

import java.io.IOException;
import java.util.UUID;
import java.util.function.Consumer;

import static org.thingsboard.server.transport.snmp.util.SnmpUtility.nextRequestId;

@Slf4j
@Component
//@ConditionalOnExpression("'${transport.type:null}'=='null' || ('${transport.type}'=='local' && '${transport.snmp.enabled}'=='true')")
public class SnmpTransportReceiverListener implements CommandResponder {

    @Getter
    @Value("${transport.snmp.listenPort}")
    private int listenPort;

    private static final String listenAddress = "127.0.0.1";

    @Autowired
    private SnmpTransportContext snmpTransportContext;

    public SnmpTransportReceiverListener() {}

    public void startSnmpListener() {
        try {
            log.info("Initializing SNMP Transport Receiver... ");
            this.listen(new UdpAddress(listenAddress + "/" + listenPort));
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

            System.out.println("Trap Type = " + pdu.getType());
            System.out.println("Variable Bindings = " + pdu.getVariableBindings());
            int pduType = pdu.getType();

            Variable payloadVar = pdu.getVariable(SnmpConstants.sysDescr);
            String payload = payloadVar.toString();
            System.out.println("payload = " + payload);
            if ((pduType == PDU.TRAP) || (pduType == PDU.NOTIFICATION)) {
                JsonObject jsonObject = new JsonParser().parse(payload).getAsJsonObject();
                String deviceToken = jsonObject.get("deviceToken").getAsString();
                String method = jsonObject.get("method").getAsString();
                if ("cxSysUptime".equalsIgnoreCase(method)) {
                    this.postToServerRpcRequest(payload, deviceToken);
                } else {
                    this.postDeviceAttributes(payload, deviceToken);
                }

            } else {
                System.out.println("Unsupported snmp request type...");
            }

            pdu.setErrorIndex(0);
            pdu.setErrorStatus(0);
            pdu.setType(PDU.RESPONSE);
            StatusInformation statusInformation = new StatusInformation();
            StateReference ref = cmdRespEvent.getStateReference();
            try {
                System.out.println("PDU =" + cmdRespEvent.getPDU());
                cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
                        cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
                        pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
            } catch (MessageException ex) {
                System.err.println("Error while sending response: " + ex.getMessage());
                LogFactory.getLogger(SnmpRequest.class).error(ex);
            }
        }
    }

    /**
     *
     * @param json
     */
    protected void postToServerRpcRequest(final String json, final String deviceToken) {
        JsonObject jsonObject = new JsonParser().parse(json).getAsJsonObject();
        snmpTransportContext.getTransportService().process(TransportProtos.ValidateDeviceTokenRequestMsg.newBuilder().setToken(deviceToken).build(),
            new SnmpTransportCallback(snmpTransportContext, (TransportProtos.SessionInfoProto sessionInfo) -> {
                JsonObject request = new JsonParser().parse(json).getAsJsonObject();
                TransportService transportService = snmpTransportContext.getTransportService();
                transportService.process(sessionInfo, TransportProtos.ToServerRpcRequestMsg.newBuilder().setRequestId(nextRequestId())
                                .setMethodName(request.get("method").getAsString())
                                .setParams(request.get("params").toString()).build(),
                        new SessionCloseOnErrorCallback(transportService, sessionInfo));
            }));
    }

    public void postDeviceAttributes(final String json, final String deviceToken) {
        JsonObject jsonObject = new JsonParser().parse(json).getAsJsonObject();
        snmpTransportContext.getTransportService().process(TransportProtos.ValidateDeviceTokenRequestMsg.newBuilder().setToken(deviceToken).build(),
                new SnmpTransportCallback(snmpTransportContext, sessionInfo -> {
                    TransportService transportService = snmpTransportContext.getTransportService();
                    transportService.process(sessionInfo, JsonConverter.convertToAttributesProto(jsonObject.getAsJsonObject("params")),
                            new SessionCloseOnErrorCallback(transportService, sessionInfo));
                }));
    }

    public void interrupt() {
        Thread.currentThread().interrupt();
    }

    private static class SnmpTransportCallback implements TransportServiceCallback<TransportProtos.ValidateDeviceCredentialsResponseMsg> {
            private final TransportContext transportContext;
            private final Consumer<TransportProtos.SessionInfoProto> onSuccess;

        public SnmpTransportCallback(TransportContext transportContext, Consumer<TransportProtos.SessionInfoProto> onSuccess) {
                this.transportContext = transportContext;
                this.onSuccess = onSuccess;
        }

        @Override
        public void onSuccess(TransportProtos.ValidateDeviceCredentialsResponseMsg msg) {
            if (msg.hasDeviceInfo()) {
                UUID sessionId = UUID.randomUUID();
                TransportProtos.DeviceInfoProto deviceInfoProto = msg.getDeviceInfo();
                TransportProtos.SessionInfoProto sessionInfo = TransportProtos.SessionInfoProto.newBuilder()
                        .setNodeId(transportContext.getNodeId())
                        .setTenantIdMSB(deviceInfoProto.getTenantIdMSB())
                        .setTenantIdLSB(deviceInfoProto.getTenantIdLSB())
                        .setDeviceIdMSB(deviceInfoProto.getDeviceIdMSB())
                        .setDeviceIdLSB(deviceInfoProto.getDeviceIdLSB())
                        .setSessionIdMSB(sessionId.getMostSignificantBits())
                        .setSessionIdLSB(sessionId.getLeastSignificantBits())
                        .build();
                onSuccess.accept(sessionInfo);
            } else {
                log.info("onSuccess:: no device info");
            }
        }

        @Override
        public void onError(Throwable e) {
            log.error("****** Failed to process request ****** ", e);
        }
    }

    private static class SessionCloseOnErrorCallback implements TransportServiceCallback<Void> {
        private final TransportService transportService;
        private final TransportProtos.SessionInfoProto sessionInfo;

        SessionCloseOnErrorCallback(TransportService transportService, TransportProtos.SessionInfoProto sessionInfo) {
            this.transportService = transportService;
            this.sessionInfo = sessionInfo;
        }

        @Override
        public void onSuccess(Void msg) {
        }

        @Override
        public void onError(Throwable e) {
            transportService.deregisterSession(sessionInfo);
        }
    }

}
