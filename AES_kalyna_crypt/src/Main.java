import util.Utils;

public class Main {

    public static void main(String[] args) {
        AES aes = new AES();

        String input = "Two One Nine Two";
        String key = "Thats my Kung Fu";

        String encripted = aes.encrypt(Utils.splitBy128Bits(input), key);
        System.out.println(encripted);

    }
}
