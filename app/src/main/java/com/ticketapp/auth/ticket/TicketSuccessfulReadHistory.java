package com.ticketapp.auth.ticket;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.HashMap;

public class TicketSuccessfulReadHistory {
    public static final int VALIDITY_PERIOD_SECONDS = 60;

    private final long readTimeSeconds;
    private final byte[] uid;

    public static HashMap<ByteBuffer, TicketSuccessfulReadHistory> successfulReadHistoryList = new HashMap<>();

    public TicketSuccessfulReadHistory(byte[] uid) {
        this.readTimeSeconds = (new Date()).getTime() / 1000;
        this.uid = uid;
        TicketSuccessfulReadHistory.successfulReadHistoryList.put(ByteBuffer.wrap(uid), this);
    }

    public long getReadTimeSeconds() {
        return readTimeSeconds;
    }


    public byte[] getUid() {
        return uid;
    }

    public boolean isExpired() {
        long currentTime = (new Date()).getTime() / 1000;
        return readTimeSeconds + VALIDITY_PERIOD_SECONDS < currentTime;
    }

}
