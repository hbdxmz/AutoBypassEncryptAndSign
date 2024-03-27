package burp;

import java.util.Random;

public class Test {
    public static void main(String[] args) {
        Random random = new Random();
        int randomNumber = random.nextInt(90000) + 10000;
        System.out.println(randomNumber);
    }
}
