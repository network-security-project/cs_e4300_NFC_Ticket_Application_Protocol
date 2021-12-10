package com.ticketapp.auth.ticket;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.HashMap;

public class TicketSuccessfulReadHistory {
    private static final int VALIDITY_PERIOD = 1;

    private final int readTime;
    private final byte[] uid;

    public static HashMap<ByteBuffer, TicketSuccessfulReadHistory> successfulReadHistoryList = new HashMap<>();

    public TicketSuccessfulReadHistory(byte[] uid) {
        this.readTime = (int) ((new Date()).getTime() / 1000 / 60);
        this.uid = uid;
        TicketSuccessfulReadHistory.successfulReadHistoryList.put(ByteBuffer.wrap(uid), this);
        System.out.println(successfulReadHistoryList.size());
    }

    public int getReadTime() {
        return readTime;
    }


    public byte[] getUid() {
        return uid;
    }

    public boolean isExpired(int currentTime) {
        return this.readTime + VALIDITY_PERIOD <= currentTime;
    }

}
