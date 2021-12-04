package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;

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
    private static final byte[] AUTHENTICATION_KEY = TicketActivity.outer.getString(R.string.master_key).getBytes();
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
    */
    private static final int PAGE_APP_TAG = 4; // size == 2 pages
    private static final int APP_TAG_SIZE = 2; // string of 8 bytes
    private static final int PAGE_ISSUING_TS = 6;
    private static final int PAGE_RIDE_COUNTER = 7;
    private static final int PAGE_ACTIVATION_TS = 8;
    private static final int PAGE_MAC = 39;
    private static final int PAGE_COUNTER = 41; // size == 2B
    private static final int PAGE_AUTH_KEY = 44; // size == 4 pages

    /*
    SAFE LIMITS
     */
    private static final int MAX_COUNTER = 65535;                   // 0xFFFF
    private static final int MAX_RIDES_ALLOWED = 50;                // max number of rides allowed for security
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
    Processes counter byte array stored on card to read it correctly (only first 2 bytes big endian).
    Returns int
     */
    public static int parseCounter(byte[] counterRead) {
        return ByteBuffer.wrap(counterRead).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /*
    * Helper for int -> byte array
    * */
    public static byte[] intToByteArray(int number) {
        return ByteBuffer.allocate(Integer.SIZE/8).putInt(number).array();
    }

    /*
    * Helper for byte array -> int
    * Little endian order needed because counter is stored
    * */
    public static int byteArrayToInt(byte[] array, boolean counter) {
        if (counter) return ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN).getInt();
        else return ByteBuffer.wrap(array).getInt();
    }

    public static String generateAuthKey(byte[] uid, byte[] masterSecret) {
        //TODO: produce key by concat and then hash
        return "";
    }

    /*
    * If card is blank, initialize with current app tag, new key, auth settings
    * */
    public static void initCard() {

        // app tag
        byte[] buff = CURRENT_APP_VERSION.getBytes();
        utils.writePages(buff, 0, PAGE_APP_TAG, APP_TAG_SIZE);

        // new key
        // TODO: update this to write actual dynamic (UID) key and not master secret
        utils.writePages(AUTHENTICATION_KEY, 0, PAGE_AUTH_KEY, 4);
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
     * 1. Check for app tag, if present, authenticate with app key and write
     *    if different, reject card
     *    if not present, initialize (write secret key)
     *
     * 2. Check safe limits
     * 3. If all go, write new ticket
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res = false;

        // read app tag and check for current version
        byte[] read = new byte[8];
        utils.readPages(4, 2, read, 0);
        String appTag = new String(read);

        // check current app tag
        if (appTag.equals(CURRENT_APP_VERSION)) {
            // proceed to auth and issuing

            res = utils.authenticate(AUTHENTICATION_KEY);
            if (res) {
                Utilities.log("[+] Authentication succeeded in issue().\n [+] Issuing ticket...", false);

                // check for reasonable number of rides
                read = new byte[4];
                utils.readPages(PAGE_COUNTER, 1, read, 0);
                int currentCounter = parseCounter(read);

                // read number of rides bought
                read = new byte[4];
                utils.readPages(PAGE_RIDE_COUNTER,1, read, 0);
                int ridesLimit = byteArrayToInt(read, false);

                //if ((ridesLimit - currentCounter) >  )

                // check number of rides left is valid && that there's enough counter for more
                // but do i separate new issuing and top up?

                infoToShow = "Ticket Issued";
            }

        } else if (appTag.trim().equals("")){

            // assuming empty card, initialize
            // can i init and make recursive call?

        } else {

            // app tag is different, reject or update?
        }

/*
        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }
*/


        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: ";
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    /**
     * Use ticket once
     * <p>
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

        // testing writing numbers
        byte[] buff = ByteBuffer.allocate(Integer.SIZE/8).putInt(447576).order(ByteOrder.BIG_ENDIAN).array();
        res = utils.writePages(buff, 0, 8, 1);

        /*
        byte[] buff = new byte[4];
        res = utils.readPages(41, 1, buff, 0);
        */

        System.out.println("#######    read: " + res);

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