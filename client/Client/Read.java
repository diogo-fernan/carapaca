package Client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Read {
    public static String OneString (){
        String s = "";
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader (System.in), 1);
            s = in.readLine();
        }
        catch (IOException e){
            System.out.println("ERROR: while reading entry flow!");
        }
        return s;
    }

    public static int OneInt(){
        while (true) {
            try {
                return Integer.valueOf(OneString().trim()).intValue();
            }
            catch (Exception e){
                System.out.println("ERROR: invalid integer!");
            }
        }
    }

    public static float OneFloat(){
        while (true) {
            try {
                return Float.valueOf(OneString().trim()).floatValue();
            }
            catch (Exception e){
                System.out.println("ERROR: invalid float!");
            }
        }
    }

    public static double OneDouble(){
        while (true) {
            try {
                return Double.valueOf(OneString().trim()).doubleValue();
            }
            catch (Exception e){
                System.out.println("ERROR: invalid double!");
            }
        }
    }

    public static boolean OneBoolean(){
        while (true) {
            try {
                return Boolean.valueOf(OneString().trim()).booleanValue();
            }
            catch (Exception e) {
                System.out.println("ERROR: invalid boolean!");
            }
        }
    }

    public static long OneLong(){
        while (true) {
            try {
                return Long.valueOf(OneString().trim()).longValue();
            }
            catch (Exception e) {
                System.out.println("ERROR: invalid long!");
            }
        }
    }
}
