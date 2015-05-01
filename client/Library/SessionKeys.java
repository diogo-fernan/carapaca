
package Library;

import java.security.PublicKey;


public class SessionKeys {
    
    public byte[] IVClient;
    public byte[] IVServer;

    public byte[] EncryptionClient;
    public byte[] EncryptionServer;

    public byte[] IntegrityClient;
    public byte[] IntegrityServer;

    public String IVClientString;
    public String IVServerString;

    public String EncryptionClientString;
    public String EncryptionServerString;

    public String IntegrityClientString;
    public String IntegrityServerString;

    public PublicKey ClientOrServerPublicKey;

    public SessionKeys() {
    }
    
    public void keysToString() {
        IVClientString = new String(IVClient);
        IVServerString = new String(IVServer);
        EncryptionClientString = new String(EncryptionClient);
        EncryptionServerString = new String(EncryptionServer);
        IntegrityClientString = new String(IntegrityClient);
        IntegrityServerString = new String(IntegrityServer);
    } 
    
    /* public String toString_Hex() {
        return  Misc.GetHex(IVClient) + ":" + 
                Misc.GetHex(IVServer) + ":" +
                Misc.GetHex(EncryptionClient) + ":" +
                Misc.GetHex(EncryptionServer) + ":" +
                Misc.GetHex(IntegrityClient) + ":" +
                Misc.GetHex(IntegrityServer);
    }
    
    @Override
    public String toString() {
        return  new String(IVClient) + ":" + 
                new String(IVServer) + ":" +
                new String(EncryptionClient) + ":" +
                new String(EncryptionServer) + ":" +
                new String(IntegrityClient) + ":" +
                new String(IntegrityServer);
    } */
}
