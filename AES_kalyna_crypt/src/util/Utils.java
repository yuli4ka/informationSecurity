package util;

import java.util.ArrayList;

public class Utils {

    public static String convertToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(String.format("%02X", aByte));
        }
        return sb.toString();
    }

    public static void printMatrix(int[][] matrix) {
        for (int[] ints : matrix) {
            for (int anInt : ints) {
                System.out.print(String.format("0x%08X", anInt) + " ");
            }
            System.out.println();
        }
        System.out.println();
    }

    public static ArrayList<String> splitBy128Bits(String input) {
        ArrayList<String> blocks = new ArrayList<>();
        int countOfBlocks = (int) Math.ceil(input.length() / 16.0);
        for (int i = 0; i < countOfBlocks; i++) {
            String block;
            if ((i * 16 + 16) > input.length())
                block = input.substring(i * 16);
            else
                block = input.substring(i * 16, i * 16 + 16);
            blocks.add(block);
        }
        return blocks;
    }
}
