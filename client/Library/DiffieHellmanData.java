
package Library;

public class DiffieHellmanData {
    
    public byte[] K;
    public byte[] X;
    public byte[] Y;
    
    public DiffieHellmanData(byte[] inK, byte[] inX, byte[] inY) {
        K = inK;
        X = inX;
        Y = inY;
    }
    
    @Override
    public String toString() {
        return  Misc.GetHex(X) + ":" +
                Misc.GetHex(Y) + ":" +
                Misc.GetHex(K);
    }
}
