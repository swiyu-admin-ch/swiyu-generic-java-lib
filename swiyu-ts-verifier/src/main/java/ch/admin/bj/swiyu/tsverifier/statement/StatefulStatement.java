package ch.admin.bj.swiyu.tsverifier.statement;

/**
 * And interface for Statements which have a state and therefore an associated status list
 */
public interface StatefulStatement {
    /**
     * Method to fetch the Status List URI from the Status List Reference encoded in the Statement
     * @return  URI where the assosiated status list can be found
     */
    String getStatusListUri();
    /**
     * Method to fetch the Status Index from the Status List Reference encoded in the Statement
     * @return Index on the Status List where the status information is stored
     */
    int getStatusIndex();
}
