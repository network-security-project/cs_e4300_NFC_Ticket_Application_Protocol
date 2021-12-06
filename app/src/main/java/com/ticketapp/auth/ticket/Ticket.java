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


    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

    /*
    * MEMORY LAYOUT
    * sizes are in number of pages except where specified
    */
    private static final int PAGE_APP_TAG = 4; // size == 2 pages
    private static final int APP_TAG_SIZE = 2; // 2 pages, string of 8 bytes
    private static final int PAGE_ISSUING_TS = 8;
    private static final int PAGE_RIDE_LIMIT_COUNTER = 6;
    private static final int PAGE_ACTIVATION_TS = 10;
    private static final int TS_SIZE = 2;  // epoch rounded to minutes = string of 8 bytes (2 pages)
    private static final int PAGE_MAC = 39;
    private static final int MAC_SIZE = 4;
    private static final int PAGE_COUNTER = 41; // size == 2B
    private static final int PAGE_AUTH_KEY = 44;
    private static final int AUTH_KEY_SIZE = 4; // 4 pages, 16 bytes
    private static final int PAGE_UID = 0;
    private static final int UID_SIZE = 2;
    private static final int PAGE_SIZE = 4; // page size is 4 bytes
    private static final int PAGE_COUNTER_LAST_VALUE = 7;
    private static final byte[] ZERO_TS = "00000000".getBytes(); // used to reset activation ts
    private static final int PAGE_AUTH0 = 42;
    private static final int PAGE_AUTH1 = 43;
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
     * Checks used in USE
     */
    public static void validateTicket(Ticket ticket) {
        ticket.isValid = true;
        ticket.remainingUses = 1;
        ticket.expiryTime = 1;
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
        return ByteBuffer.allocate(Integer.SIZE/8).order(ByteOrder.LITTLE_ENDIAN).putInt(number).array();
    }

    /**
     * Helper function for extracting UID from read buffer of 8 byte
     * */
    public static byte[] getUID(byte[] array) {
        return new byte[]{array[0], array[1], array[2], array[4], array[5], array[6], array[7]};
    }

    /**
    * Generate unique authentication key by hashing ( uid | secret )
    * @param uid card's UID
    * @param masterSecret common master secret
    * @return byte array of generated key of size 256bits = 16bytes
    */
    public static byte[] generateAuthKey(byte[] uid, byte[] masterSecret) {

        byte[] data = new byte[uid.length + masterSecret.length];
        System.arraycopy(uid, 0, data, 0, uid.length);
        System.arraycopy(masterSecret,0, data, uid.length, masterSecret.length);
        byte[] key = null;

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            key = sha256.digest(data);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return key;
    }

    /**
    * If card is blank, initialize with current app tag, new key, auth settings
    */
    public static boolean initCard() {
        boolean res = false;

        // app tag
        byte[] buff = CURRENT_APP_VERSION.getBytes();
        res = utils.writePages(buff, 0, PAGE_APP_TAG, APP_TAG_SIZE);

        // uid
        byte[] uid = new byte[8];
        res = res && utils.readPages(PAGE_UID, UID_SIZE, buff, 0);

        // new key
        byte[] authKey = generateAuthKey(getUID(uid), MASTER_SECRET);
        res = res && utils.authenticate(DEFAULT_AUTHENTICATION_KEY);
        res = res && utils.writePages(authKey, 0, PAGE_AUTH_KEY, AUTH_KEY_SIZE);

        /*
        // lock read/write page with auth bits
        utils.writePages(intToByteArray(AUTH0_START_ADDRESS), 0, PAGE_AUTH0, 1);
        utils.writePages(intToByteArray(AUTH1_MODE), 0, PAGE_AUTH1, 1);
        */

        return res;
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
     *
     * 1. Check for app tag, if present, authenticate with unique key and write
     *    if different, reject card
     *    if not present, initialize (write new key)
     * 2. Check safe limits
     * 3. On first issue, activation date should be blank;
     *    if topping up rides, activation should be reset to 0 so
     *    that in use() we can use the field to understand whether the ticket
     *    is to be activated or already in use
     * 4. update issuing timestamp
     * 5. MAC info
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res = false;
        infoToShow = "Issuing failed.";

        // read app tag and check for current version
        byte[] read = new byte[8];
        utils.readPages(PAGE_APP_TAG, APP_TAG_SIZE, read, 0);
        String appTag = new String(read);
        System.out.println("++++++       read tag: " + appTag);

        if (!appTag.equals(CURRENT_APP_VERSION) && !appTag.trim().equals("")) {
            // foreign card, reject it
            Utilities.log("[?] Found foreign card, stopping issuing...", true);
            throw new GeneralSecurityException("Unrecognized card supplied!");

        } else if (appTag.trim().equals("")) {
            // card's a new one, init and continue

            if (!initCard()) {
                Utilities.log("[!] Initialization of new card failed", true);
                throw new GeneralSecurityException("Failed to initialize new card.");
            }

        }

        // proceed to issuing
        byte[] uid = new byte[UID_SIZE * PAGE_SIZE];
        utils.readPages(PAGE_UID, UID_SIZE, uid, 0);
        byte[] key = generateAuthKey(uid, MASTER_SECRET);

        res = utils.authenticate(key);

        if (res) {

            boolean success;
            Utilities.log("[+] Authentication succeeded in issue().\n [+] Issuing ticket...", false);

            // check for reasonable number of rides
            read = new byte[4];
            utils.readPages(PAGE_COUNTER, 1, read, 0);
            int currentCounter = byteArrayToInt(read);

            // read number of rides bought
            read = new byte[4];
            utils.readPages(PAGE_RIDE_LIMIT_COUNTER,1, read, 0);
            int ridesLimitCounter = byteArrayToInt(read);

            if (((MAX_COUNTER_VALUE - currentCounter) < MIN_RIDES_ALLOWED) &&
                    ((ridesLimitCounter - currentCounter) >= MAX_RIDES_ALLOWED) &&
                    ((ridesLimitCounter - currentCounter < 0))) {
                // either card EOL or fishy number of rides available, reject
                Utilities.log("Issuing rejected.", true);
                throw new GeneralSecurityException("Issuing failed due to safe limits.");
            }

            // store backup of current counter
            success = utils.writePages(intToByteArray(currentCounter), 0, PAGE_COUNTER_LAST_VALUE, 1);

            // write new limit counter target after incrementing with newly bought rides
            int newRidesLimit = ridesLimitCounter + uses;
            success = success && utils.writePages(intToByteArray(newRidesLimit), 0, PAGE_RIDE_LIMIT_COUNTER, 1);

            // reset activation date
            success = success && utils.writePages(ZERO_TS, 0, PAGE_ACTIVATION_TS, TS_SIZE);

            // commit issuing TS
            String currentTime = String.valueOf(System.currentTimeMillis() / 1000 / 60); // round current time to minutes from epoch (8 bytes)
            success = success && utils.writePages(currentTime.getBytes(), 0, PAGE_ISSUING_TS, TS_SIZE);

            // MAC it up
            // FORMAT for MAC input is: ( app_tag:limit_counter:last_counter:issue_ts:activation_ts )
            String macData = CURRENT_APP_VERSION + ":" +
                    String.valueOf(newRidesLimit) + ":" +
                    String.valueOf(currentCounter) + ":" +
                    currentTime +
                    new String(ZERO_TS);

            byte[] mac = macAlgorithm.generateMac(macData.getBytes());
            success = success && utils.writePages(mac, 0, PAGE_MAC, MAC_SIZE);

            if (success) {
                infoToShow = "Ticket issued.";
                return true;
            }

            Utilities.log("A write failed during the issuing, aborting...", true);
            throw new GeneralSecurityException("Issuing failed");

        }

        Utilities.log("Why am I even here?", true);
        return false;
    }


    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(DEFAULT_AUTHENTICATION_KEY);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // uid
        byte[] buff = new byte[8];
        res = utils.readPages(PAGE_UID, UID_SIZE, buff, 0);
        byte[] uid = getUID(buff);

        // new key
        byte[] authKey = generateAuthKey(getUID(buff), MASTER_SECRET);
        res = utils.authenticate(authKey);

        //Validate
//        Ticket.validateTicket(this);


        // Set information to show for the user
        if (res) {
            infoToShow = "Read: ";
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}