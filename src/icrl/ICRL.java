/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package icrl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 *
 * @author Rachmawan
 */
public class ICRL {

    private static final boolean debug = true;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        //ReadP12("D:\\Tugas PTIK\\Certificate Authority\\Study PKI\\ajinorev_Backup.p12", "aji123456");
        ReadP12("D:\\Tugas PTIK\\Certificate Authority\\Study PKI\\ajirev.p12", "aji123456");
    }

    public static void ReadP12(String filename, String password) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//        String crl_str = "";

//        byte[] issuerKeyHash = null, issuerNameHash = null;
        BigInteger serial_number = new BigInteger("0");

        KeyStore my_KS;
        
        try {
            my_KS = KeyStore.getInstance("PKCS12");
            File f = new File(filename);
            FileInputStream is = new FileInputStream(f);
            my_KS.load(is, password.toCharArray());

            BigInteger bi_serial = new BigInteger("0");
            Enumeration enumeration = my_KS.aliases();
            
            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                if (debug) {
                    System.out.println("alias name: " + alias);
                }

                PrivateKey key = (PrivateKey) my_KS.getKey(alias, password.toCharArray());

                java.security.cert.Certificate[] cchain = my_KS.getCertificateChain(alias);

                int chain_idx = 0;
                for (Certificate chain_list : cchain) 
                {
                    X509Certificate c = (X509Certificate) chain_list;
                    org.bouncycastle.asn1.x509.Certificate c2 = org.bouncycastle.asn1.x509.Certificate.getInstance(c.getEncoded());
                    Principal subject = c.getSubjectDN();
                    PublicKey the_PK = c.getPublicKey();
                    
                    if (chain_idx == 0) {
                        serial_number = c.getSerialNumber();
                        
                        iCRLVerifier.verifyCertificateCRLs(c);
                    }
                }
                
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | CertificateVerificationException ex) {
            Logger.getLogger(ICRL.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(ICRL.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ICRL.class.getName()).log(Level.SEVERE, null, ex);
        }
            
    }

}
