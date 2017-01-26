/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package icrl;

/**
 *
 * @author Rachmawan
 */
public class CertificateVerificationException extends Exception{
    private static final long serialVersionUID = 1L;
 
    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
 
    public CertificateVerificationException(String message) {
        super(message);
    }
}
