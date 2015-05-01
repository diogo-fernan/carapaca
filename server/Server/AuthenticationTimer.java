package Server;

import java.util.Timer;
import java.util.TimerTask;


public class AuthenticationTimer {
    private Timer timer;
    private Signal signal;
    private int seconds;
    
    public AuthenticationTimer(Signal inSignal) {
        seconds = 30;
        signal = inSignal;
        timer = new Timer();
        timer.schedule(new CountDown(),
	               0,        
	               seconds * 1000);
    }
    
    public void Terminate() {
        timer.cancel();
    }

    class CountDown extends TimerTask {
        @Override
        public void run() {
            // System.out.println(" beep!");
            signal.TimeIsUp();
        }
    }
}
