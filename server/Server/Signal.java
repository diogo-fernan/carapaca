package Server;


public class Signal {
    
    private boolean signal;
    
    public Signal() {
        signal = false;
    }
    
    public synchronized void TimeIsUp() {
        signal = true;
    }
    public synchronized boolean CheckSignal() {
        return signal;
    }
    public synchronized void ResetSignal() {
        signal = false;
    }
}
