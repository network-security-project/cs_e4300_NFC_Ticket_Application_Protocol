package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
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
    public static int counterFromArray(byte[] counterRead) {
        byte[] toReturn = {0x00, 0x00, counterRead[1], counterRead[0]};
        return ByteBuffer.wrap(toReturn).getInt();
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
        boolean res;

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
                utils.readPages(41, 1, read, 0);
                int currentCounter = counterFromArray(read);

                // read number of rides bought
                read = new byte[4];
                utils.readPages(0,1, read, 0);
                // int ridesAvailable = counterFromArray() // or parse  || update function?

                // check number of rides left is valid && that there's enough counter for more

                infoToShow = "Ticket Issued";
            }

        } else if (appTag.trim().equals("")){
            // initialize

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



        // Example of writing:

        byte[] message = "SLMD".getBytes();
        res = utils.writePages(message, 0, 15, 1);
        System.out.println(res);

        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: " + new String(message);
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
        res = utils.authenticate(AUTHENTICATION_KEY);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        //Validate
        Ticket.validateTicket(this);


        // Example of reading:
        byte[] message = new byte[4];
        res = utils.readPages(11, 1, message, 0);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}