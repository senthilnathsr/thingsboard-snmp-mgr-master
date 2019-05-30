package org.thingsboard.server.transport.snmp.util;

/**
 *
 */
public class SnmpUtility {
    public static int nextRequestId() {
        return org.apache.commons.lang3.RandomUtils.nextInt(100000, 999999);
    }
}
