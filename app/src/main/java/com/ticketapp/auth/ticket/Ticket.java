package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] DEFAULT_AUTHENTICATION_KEY = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] DEFAULT_HMAC_KEY = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();
    private static final byte[] MASTER_SECRET = TicketActivity.outer.getString(R.string.master_key).getBytes();
    private static final byte[] HMAC_KEY = TicketActivity.outer.getString(R.string.hmac_key).getBytes();

    /*
    Values for issue
    * */
    private static final int TICKET_USES = 10;
    private static final int MINUTES_VALID = 30;


    public static byte[] data = new byte[192];


    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = true;
    private int remainingUses = 0;
    private int expiryTime = 0;
    private int currentCounter = 0;
    private int limitCounter = 0;
    private int pastCounter = 0;

    /*
     * MEMORY LAYOUT
     * sizes are in number of pages except where specified
     */
    private static final int PAGE_UID = 0;
    private static final int PAGE_APP_TAG = 4; // size == 2 pages
    private static final int PAGE_RIDE_LIMIT_COUNTER = 6;
    private static final int PAGE_ISSUING_TS = 8;
    private static final int PAGE_ACTIVATION_TS = 9;
    private static final int PAGE_MAC = 39;
    private static final int PAGE_COUNTER = 41; // size == 2B
    private static final int PAGE_AUTH_KEY = 44;
    private static final int PAGE_SIZE = 4; // page size is 4 bytes
    private static final int PAGE_COUNTER_LAST_VALUE = 7;
    private static final int PAGE_AUTH0 = 42;
    private static final int PAGE_AUTH1 = 43;
    private static final int APP_TAG_SIZE = 2; // 2 pages, string of 8 bytes
    private static final int TS_SIZE = 1;  // epoch rounded to minutes = int of 4 bytes (1 page)
    private static final int MAC_SIZE = 1;
    private static final int AUTH_KEY_SIZE = 4; // 4 pages, 16 bytes
    private static final int UID_SIZE = 2; // read of 2 pages, use getUID() to extract 7byte id
    private static final int COUNTER_SIZE = 1;
    private static final int COMMON_DATA_SIZE = APP_TAG_SIZE + COUNTER_SIZE + COUNTER_SIZE + TS_SIZE + TS_SIZE;
    private static final int ZERO_TS = 0; // used to reset activation ts
    private static final int AUTH0_START_ADDRESS = 6; // r/w protect memory leaving app tag readable
    private static final int AUTH1_MODE = 0; // r/w restricted

    /*
    SAFE LIMITS
     */
    private static final int MAX_COUNTER_VALUE = 65535;                   // 0xFFFF
    private static final int MAX_RIDES_ALLOWED = 100;                // max number of rides allowed for security
    private static final int MIN_RIDES_ALLOWED = 30;                // card reached EOL
    private static final String CURRENT_APP_VERSION = "NFC0.0.0";   // app tag

    private static String infoToShow = "-"; // Use this to show messages
    private String failureReason = "-"; // Use this to show the user the reason of a possible failure

    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(HMAC_KEY);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /*
     * Parse common data into variables
     * */
    private void serializeCommonData(byte[] commonData) {

        int start = APP_TAG_SIZE * PAGE_SIZE;
        limitCounter = byteArrayToInt(Arrays.copyOfRange(commonData, start,
                start + (COUNTER_SIZE * PAGE_SIZE)));

        start += (COUNTER_SIZE * PAGE_SIZE);

        pastCounter = byteArrayToInt(Arrays.copyOfRange(commonData, start,
                start + (COUNTER_SIZE * PAGE_SIZE)));

        start += (COUNTER_SIZE * PAGE_SIZE);

        expiryTime = byteArrayToInt(Arrays.copyOfRange(commonData, start,
                start + (COUNTER_SIZE * PAGE_SIZE))) + MINUTES_VALID;

        this.currentCounter = readCounter();

        remainingUses = limitCounter - this.currentCounter;

    }

    /*
     * Checks used in USE
     */
    private void validateTicket(byte[] commonData, byte[] cardMAC, int currentTime) {
        byte[] calculatedMAC = Arrays.copyOfRange(macAlgorithm.generateMac(commonData), 0,
                MAC_SIZE * PAGE_SIZE);

        if (Arrays.equals(calculatedMAC, cardMAC)) {
            serializeCommonData(commonData);
            if (this.remainingUses <= 0) {
                this.isValid = false;
                failureReason = "No more rides left";
                return;
            }

            if (this.expiryTime <= currentTime) {
                this.isValid = false;
                failureReason = "The ticket has expired";
                return;
            }

            if (this.remainingUses > MAX_RIDES_ALLOWED) {
                this.isValid = false;
                failureReason = "Ticket has unreasonable number of rides";
                return;
            }

            this.isValid = true;

        } else {
            this.isValid = false;
            failureReason = "MAC mismatch";
        }
    }

    /*
     * Helper for byte array -> int
     * Every number, counter included, is little endian in memory
     * */
    public static int byteArrayToInt(byte[] counterRead) {
        return ByteBuffer.wrap(counterRead).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /*
     * Helper for int -> byte array
     * By using this function only we are writing every number in little endian
     * */
    public static byte[] intToByteArray(int number) {
        return ByteBuffer.allocate(Integer.SIZE / 8).order(ByteOrder.LITTLE_ENDIAN).putInt(number).array();
    }

    /**
     * Helper function for extracting UID from read buffer of 8 byte
     */
    public static byte[] getUID(byte[] array) {
        return new byte[]{array[0], array[1], array[2], array[4], array[5], array[6], array[7]};
    }

    /**
     * Generate unique authentication key by hashing ( uid | secret )
     *
     * @param uid          card's UID
     * @param masterSecret common master secret
     * @return byte array of generated key of size 256bits = 16bytes
     */
    public static byte[] generateAuthKey(byte[] uid, byte[] masterSecret) {

        byte[] data = concatAll(uid, masterSecret);
        byte[] key = null;

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            key = sha256.digest(data);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return key;
    }

    public static byte[] concatAll(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    /**
     * If card is blank, initialize with current app tag, new key, auth settings
     */
    public static byte[] generateCommonData(int currentCounter, int counterLimit, int uses) {
        int issueTS = (int) ((new Date()).getTime() / 1000 / 60);
        int newCounterLimit;

        if (counterLimit < currentCounter) {
            newCounterLimit = currentCounter + uses;
        } else {
            newCounterLimit = counterLimit + uses;
        }

        return concatAll(
                CURRENT_APP_VERSION.getBytes(),
                intToByteArray(newCounterLimit),
                intToByteArray(currentCounter),
                intToByteArray(issueTS),
                intToByteArray(ZERO_TS)
        );
    }

    private byte[] readCommonData() {
        byte[] buff = new byte[COMMON_DATA_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_APP_TAG, COMMON_DATA_SIZE, buff, 0);
        return buff;
    }

    private byte[] readUID() {
        byte[] uid = new byte[UID_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_UID, UID_SIZE, uid, 0);
        return getUID(uid);
    }

    private byte[] readMAC() {
        byte[] mac = new byte[MAC_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_MAC, MAC_SIZE, mac, 0);
        return mac;
    }

    private int readCounter() {
        byte[] counter = new byte[COUNTER_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_COUNTER, COUNTER_SIZE, counter, 0);
        return byteArrayToInt(counter);
    }

    public static boolean resetAppTag() {
        return utils.writePages("        ".getBytes(), 0, PAGE_APP_TAG, APP_TAG_SIZE);
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * After validation, get the number of remaining uses
     */
    public int getRemainingUses() {
        return remainingUses;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * Issue new tickets
     * <p>
     * 1. Check for app tag, if present, authenticate with unique key and write
     * if different, reject card
     * if not present, initialize (write new key)
     * 2. Check safe limits
     * 3. On first issue, activation date should be blank;
     * if topping up rides, activation should be reset to 0 so
     * that in use() we can use the field to understand whether the ticket
     * is to be activated or already in use
     * 4. update issuing timestamp
     * 5. MAC info
     */
    public boolean issue() throws GeneralSecurityException {
        boolean res;
        boolean init = true;
        infoToShow = "Issuing failed.";

        // read app tag and check for current version
        byte[] read = new byte[8];
        utils.readPages(PAGE_APP_TAG, APP_TAG_SIZE, read, 0);
        String appTag = new String(read);
        System.out.println("++++++       read tag: " + appTag);

        if (!appTag.equals(CURRENT_APP_VERSION)) {
            // foreign card, reject it
            Utilities.log("[?] Found foreign card, stopping issuing...", true);
            throw new GeneralSecurityException("Unrecognized card supplied!");
        }

        // read uid and generate unique authentication key
        byte[] key = generateAuthKey(readUID(), MASTER_SECRET);

        int currentLimit = 0;
        byte[] buff = new byte[PAGE_SIZE * COUNTER_SIZE];

        // read current counter
        currentCounter = readCounter();

        if (currentCounter == 0) {
            // card's a new one, init counter, limit, key and continue
            // FOR SECURITY, WRITE CURRENT COUNTER VALUE TO LIMIT VALUE
            init = utils.readPages(PAGE_COUNTER, COUNTER_SIZE, buff, 0);

            init = init && utils.writePages(intToByteArray(0), 0, PAGE_COUNTER, COUNTER_SIZE);
            init = init && utils.writePages(key, 0, PAGE_AUTH_KEY, AUTH_KEY_SIZE);
        } else {
            // reused card, authenticate
            boolean authResult = utils.authenticate(key);

            if (!authResult) {
                throw new GeneralSecurityException("Authentication failed!");
            }

            // and read current limit
            utils.readPages(PAGE_RIDE_LIMIT_COUNTER, COUNTER_SIZE, buff, 0);
            currentLimit = byteArrayToInt(buff);

            if ((currentCounter + TICKET_USES > MAX_COUNTER_VALUE) &&
                    (currentLimit - currentCounter + TICKET_USES < MAX_RIDES_ALLOWED)) {
                Utilities.log("Safe limits exceeded, aborting...", true);
                throw new GeneralSecurityException("Counter value exceeds! try New Card");
            }
        }

        byte[] commonData = generateCommonData(currentCounter, currentLimit, TICKET_USES);
        byte[] mac = macAlgorithm.generateMac(commonData);

        res = utils.writePages(commonData, 0, PAGE_APP_TAG, COMMON_DATA_SIZE);
        res = res && utils.writePages(mac, 0, PAGE_MAC, MAC_SIZE);
        utils.writePages(intToByteArray(AUTH0_START_ADDRESS), 0, PAGE_AUTH0, 1);
        utils.writePages(intToByteArray(AUTH1_MODE), 0, PAGE_AUTH1, 1);

        if (init && res) {
            infoToShow = "Ticket issued.";
            return true;
        }

        return false;
    }


    /**
     * Use ticket once
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
        byte[] uid = readUID();

        TicketSuccessfulReadHistory uidHistory = TicketSuccessfulReadHistory.
                successfulReadHistoryList.get(ByteBuffer.wrap(uid));
        if (uidHistory != null && !uidHistory.isExpired(currentTime)) {
            infoToShow = "This ticket has been used in the past " +
                    TicketSuccessfulReadHistory.VALIDITY_PERIOD + " minutes";
            return false;
        }

        byte[] key = generateAuthKey(uid, MASTER_SECRET);
        boolean authResult = utils.authenticate(key);

        if (!authResult) {
            infoToShow = "Authentication Failed!";
            return false;
        }

        byte[] commonData = readCommonData();

        // Validate
        this.validateTicket(commonData, readMAC(), currentTime);
        if (this.isValid) {
            boolean res = true;

            if (this.pastCounter == this.currentCounter) {
                // first use
                System.arraycopy(intToByteArray(currentTime), 0, commonData,
                        (COMMON_DATA_SIZE - TS_SIZE) * PAGE_SIZE, TS_SIZE * PAGE_SIZE);
                byte[] mac = macAlgorithm.generateMac(commonData);

                res = utils.writePages(mac, 0, PAGE_MAC, MAC_SIZE);
                res = res && utils.writePages(intToByteArray(currentTime), 0, PAGE_ACTIVATION_TS,
                        TS_SIZE);
            }

            res = res && utils.writePages(intToByteArray(1), 0, PAGE_COUNTER,
                    COUNTER_SIZE);

            // Set information to show for the user
            if (res) {
                infoToShow = "Ticket used!\nAvailable rides: " +
                        this.remainingUses + "\nExpiry time: " + new Date((long) expiryTime * 60 * 1000);
                new TicketSuccessfulReadHistory(uid);
                return true;
            } else {
                infoToShow = "Failed to read, Hold longer";
                return false;
            }

        } else {
            infoToShow = "Ticket not valid: " + failureReason;
            return false;
        }

    }


    private static void checkMAC() throws GeneralSecurityException {
        boolean res = true;
        byte[] uid = new byte[UID_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_UID, UID_SIZE, uid, 0);
        byte[] key = generateAuthKey(getUID(uid), MASTER_SECRET);

        // Authenticate
        res = utils.authenticate(key);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            throw new GeneralSecurityException("AUTH failed");
        }

        byte[] data = new byte[PAGE_SIZE * COMMON_DATA_SIZE];
        utils.readPages(PAGE_APP_TAG, COMMON_DATA_SIZE, data, 0);

        byte[] readMac = new byte[MAC_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_MAC, MAC_SIZE, readMac, 0);

        byte[] MAC = Arrays.copyOfRange(macAlgorithm.generateMac(data), 0,
                MAC_SIZE * PAGE_SIZE);

        if (Arrays.equals(readMac, MAC)) System.out.println("[!!!] mac matched");
        else Utilities.log("mac not matched", true);
    }
}


