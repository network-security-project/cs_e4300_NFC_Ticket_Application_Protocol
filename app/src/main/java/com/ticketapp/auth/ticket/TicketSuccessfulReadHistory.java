package com.ticketapp.auth.ticket;

import java.util.Date;
import java.util.HashMap;

public class TicketSuccessfulReadHistory {
    private static final int VALIDITY_PERIOD = 5;

    private final int readTime;
    private final byte[] uid;

    public static HashMap<byte[], TicketSuccessfulReadHistory> successfulReadHistoryList = new HashMap<>();

    public TicketSuccessfulReadHistory(byte[] uid) {
        this.readTime = (int) ((new Date()).getTime() / 1000 / 60);
        this.uid = uid;
        TicketSuccessfulReadHistory.successfulReadHistoryList.put(uid, this);
    }

    public int getReadTime() {
        return readTime;
    }


    public byte[] getUid() {
        return uid;
    }

    public boolean isExpired(int currentTime) {
        return this.readTime + VALIDITY_PERIOD < currentTime;
    }

}
