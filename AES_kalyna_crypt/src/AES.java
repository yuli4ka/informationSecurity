import java.util.ArrayList;
import java.util.Arrays;

import static util.Utils.*;

public class AES {

    private static int[][] SBOX = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    private static int[][] INV_SBOX = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    private static int[][] R_CON =
            {{0, 1, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a},
                    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};


    private static int[][] galoisMatrix = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}};

    private static int[][] invGaloisMatrix = {
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e}};

    int keyLength = 128;
    int totalWords = 44;
    private int nk = 4;
    private int nr = 10;
    private int[][] w;
    private int[][] stateMatrix;
    private StringBuilder sb = new StringBuilder();

    public AES(int keyLength) {
        if (keyLength == 192) {
            this.nk = 6;
            this.nr = 12;
            totalWords = 52;
            this.keyLength = keyLength;
        } else if (keyLength == 256) {
            this.nk = 8;
            this.nr = 14;
            totalWords = 60;
            this.keyLength = keyLength;
        }
        w = new int[totalWords][4];
    }

    public AES() {
        w = new int[totalWords][4];
    }

    public String encrypt(ArrayList<String> inputs, String key) {
        String KeyTextHex = convertToHexString(key.getBytes());
        int keyLength = key.length();
        int[][] keysHexMatrix = matrixHex(KeyTextHex, keyLength, nk);

        for (String input : inputs) {
            String InputTextHex = convertToHexString(input.getBytes());
            int textLength = input.length();
            int[][] hexInputMatrix = matrixHex(InputTextHex, textLength, nk);

            doEncryption(hexInputMatrix, keysHexMatrix);
            for (int k = 0; k < 4; k++) {
                for (int j = 0; j < 4; j++) {
                    sb.append(Integer.toHexString(stateMatrix[k][j]) + " ");
                }
            }
        }
        System.out.println("Crypted text: " + sb.toString());
        return sb.toString();
    }

    private void doEncryption(int[][] state, int[][] keys) {
        stateMatrix = state;
        initialiseInitialWords(keys);
        generateWords();

        addRoundKey(stateMatrix, getKeysForRound(0));

        for (int round = 1; round < nr; round++) {
            executeRound(round);
        }
        subBytes(stateMatrix);
        shiftRows(stateMatrix);
        addRoundKey(stateMatrix, getKeysForRound(nr));
    }

    public int[][] doDecryption(int[][] state, int[][] keys) {
        stateMatrix = state;
        initialiseInitialWords(keys);
        generateWords();

        addRoundKey(stateMatrix, getKeysForRound(nr));

        for (int round = nr-1; round >0; round--) {
            executeDecryptRound(round);
        }

        invShiftRows(stateMatrix);
        invSubBytes(stateMatrix);
        addRoundKey(stateMatrix, getKeysForRound(0));
        return stateMatrix;
    }

    private void invSubBytes(int[][] stateMatrix) {
        for (int i = 0; i < stateMatrix.length; i++) {
            for (int j = 0; j < stateMatrix[0].length; j++) {
                int hex = stateMatrix[i][j];
                stateMatrix[i][j] = invSubBytesReplace(hex);
            }
        }
    }

    private int invSubBytesReplace(int hex) {
        String HexString = Integer.toHexString(hex);
        if (HexString.length() == 1) {
            HexString = "0" + HexString;
        }
        String x1 = HexString.substring(0, 1);
        String x2 = HexString.substring(1, 2);
        int row = Integer.parseInt(x1, 16);
        int column = Integer.parseInt(x2, 16);
        return INV_SBOX[row][column];
    }

    private void invShiftRows(int[][] stateMatrix) {
        for (int i = 1; i < stateMatrix.length; i++) {
            stateMatrix[i] = shiftRight(stateMatrix[i], i);
        }
    }

    private int[] shiftRight(int[] row, int moves) {
        while (moves > 0) {
            int temp = row[row.length - 1];
            for (int i = row.length - 1; i > 0; i--) {
                row[i] = row[i - 1];
            }
            row[0] = temp;
            moves--;
        }
        return row;
    }

    private void executeDecryptRound(int round) {
        invShiftRows(stateMatrix);
        invSubBytes(stateMatrix);
        addRoundKey(stateMatrix, getKeysForRound(round));
        invMixColumns(stateMatrix);
    }

    private void invMixColumns(int[][] stateMatrix) {
        int[] column1 = new int[4];
        int[] column2 = new int[4];
        int[] column3 = new int[4];
        int[] column4 = new int[4];
        for (int i = 0; i < 4; i++) {
            column1[i] = stateMatrix[i][0];
        }
        for (int i = 0; i < 4; i++) {
            column2[i] = stateMatrix[i][1];
        }
        for (int i = 0; i < 4; i++) {
            column3[i] = stateMatrix[i][2];
        }
        for (int i = 0; i < 4; i++) {
            column4[i] = stateMatrix[i][3];
        }

        MultiplyMatrixByInvGalois(column1);
        MultiplyMatrixByInvGalois(column2);
        MultiplyMatrixByInvGalois(column3);
        MultiplyMatrixByInvGalois(column4);
        int[] array1and4 = new int[column1.length + column2.length + column3.length + column4.length];
        System.arraycopy(column1, 0, array1and4, 0, column2.length);
        System.arraycopy(column2, 0, array1and4, column1.length, column2.length);
        System.arraycopy(column3, 0, array1and4, column1.length + column2.length, column3.length);
        System.arraycopy(column4, 0, array1and4, column1.length + column2.length + column3.length, column4.length);

        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[j][i] = array1and4[k];
                k++;

            }
        }
    }

    private void shiftRows(int[][] stateMatrix) {
        for (int i = 1; i < stateMatrix.length; i++) {
            stateMatrix[i] = shiftLeft(stateMatrix[i], i);
        }
    }

    private int[] shiftLeft(int[] row, int moves) {
        while (moves > 0) {
            int temp = row[0];
            for (int i = 0; i < row.length - 1; i++) {
                row[i] = row[i + 1];
            }
            row[row.length - 1] = temp;
            moves--;
        }
        return row;
    }

    private void subBytes(int[][] stateMatrix) {
        for (int i = 0; i < stateMatrix.length; i++) {
            for (int j = 0; j < stateMatrix[0].length; j++) {
                int hex = stateMatrix[i][j];
                stateMatrix[i][j] = subBytesReplace(hex);
            }
        }
    }

    private void executeRound(int round) {
        subBytes(stateMatrix);
        shiftRows(stateMatrix);
        mixColumns(stateMatrix);
        addRoundKey(stateMatrix, getKeysForRound(round));
    }

    private void mixColumns(int[][] stateMatrix) {
        int[] column1 = new int[4];
        int[] column2 = new int[4];
        int[] column3 = new int[4];
        int[] column4 = new int[4];
        for (int i = 0; i < 4; i++) {
            column1[i] = stateMatrix[i][0];
        }
        for (int i = 0; i < 4; i++) {
            column2[i] = stateMatrix[i][1];
        }
        for (int i = 0; i < 4; i++) {
            column3[i] = stateMatrix[i][2];
        }
        for (int i = 0; i < 4; i++) {
            column4[i] = stateMatrix[i][3];
        }

        MultiplyMatrixByGalois(column1);
        MultiplyMatrixByGalois(column2);
        MultiplyMatrixByGalois(column3);
        MultiplyMatrixByGalois(column4);
        int[] array1and4 = new int[column1.length + column2.length + column3.length + column4.length];
        System.arraycopy(column1, 0, array1and4, 0, column2.length);
        System.arraycopy(column2, 0, array1and4, column1.length, column2.length);
        System.arraycopy(column3, 0, array1and4, column1.length + column2.length, column3.length);
        System.arraycopy(column4, 0, array1and4, column1.length + column2.length + column3.length, column4.length);

        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[j][i] = array1and4[k];
                k++;
            }
        }
    }

    private void addRoundKey(int[][] stateMatrix, int[][] keys) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[j][i] = stateMatrix[j][i] ^ keys[j][i];
            }
        }
    }

    private int[][] getKeysForRound(int round) {
        int[][] keys = new int[4][4];
        int[][] wordsForRound = Arrays.copyOfRange(w, round * 4, round * 4 + 4);

        for (int k = 0; k < 4; k++) {
            for (int z = 0; z < 4; z++) {
                keys[z][k] = wordsForRound[k][z];
            }
        }
        System.out.println("Keys for round " + round + " :");
        printMatrix(keys);
        return keys;
    }

    private void generateWords() {
        int[] temp = getWord(nk - 1);

        for (int i = nk; i < (4 * (nr + 1)); i++) {
            System.arraycopy(w[i - 1], 0, temp, 0, 4);

            if (i % nk == 0) {
                int[] rotted = rotWord(temp);
                System.arraycopy(rotted, 0, temp, 0, 4);

                int[] subWorded = subWord(temp);
                System.arraycopy(subWorded, 0, temp, 0, 4);

                for (int t = 0; t < 4; t++)
                    temp[t] ^= R_CON[t][i / nk];
            }
            else if (nk > 6 && i % nk == 4) {
                int[] subWorded = subWord(temp);
                System.arraycopy(subWorded, 0, temp, 0, 4);
            }
            for (int t = 0; t < 4; t++) {
                w[i][t] = w[i - nk][t] ^ temp[t];
            }
        }
    }

    private int[] subWord(int[] word) {
        int[] subWordArray = new int[4];
        for (int i = 0; i < 4; i++)
            subWordArray[i] = subBytesReplace(word[i]);
        return subWordArray;
    }

    private int subBytesReplace(int hex) {
        String HexString = Integer.toHexString(hex);
        if (HexString.length() == 1) {
            HexString = "0" + HexString;
        }
        String x1 = HexString.substring(0, 1);
        String x2 = HexString.substring(1, 2);
        int row = Integer.parseInt(x1, 16);
        int column = Integer.parseInt(x2, 16);
        return SBOX[row][column];
    }

    private int[] rotWord(int[] word) {
        int[] rotWordArray = new int[4];
        int tmp = word[0];
        System.arraycopy(word, 1, rotWordArray, 0, 3);
        rotWordArray[3] = tmp;
        return rotWordArray;
    }

    private int[] getWord(int i) {
        int[] key = new int[4];
        key[0] = w[i][0];
        key[1] = w[i][1];
        key[2] = w[i][2];
        key[3] = w[i][3];
        return key;
    }

    private void initialiseInitialWords(int[][] keys) {
        for (int i = 0; i < nk; i++) {
            w[i][0] = keys[0][i];
            w[i][1] = keys[1][i];
            w[i][2] = keys[2][i];
            w[i][3] = keys[3][i];
        }
    }

    private int[][] matrixHex(String inputTextHex, int inputLength, int nk) {
        int[][] state = new int[4][nk];
        int k = 0, m = -2, c = 0;
        for (int i = 0; i < nk; i++) {
            for (int j = 0; j < 4; j++) {
                k += 2;
                m += 2;
                c++;
                state[j][i] = Integer.parseInt(inputTextHex.substring(m, k), 16);
                if (c == inputLength) {
                    return state;
                }
            }
        }
        return state;
    }

    public static void MultiplyMatrixByGalois(int[] column) {
        int[] columnCopy = new int[4];
        System.arraycopy(column, 0, columnCopy, 0, columnCopy.length);

        for (int i = 0; i < 4; i++) {
            int result = 0;
            for (int j = 0; j < 4; j++) {
                result ^= galoisMultiply(galoisMatrix[i][j], columnCopy[j]);
            }
            column[i] = result;
        }
    }

    private static int galoisMultiply(int a, int b) {
        int p = 0;
        for (int n = 0; n < 8; n++) {
            p = ((b & 0x01) > 0) ? p ^ a : p;
            boolean ho = ((a & 0x80) > 0);
            a = ((a << 1) & 0xFE);
            if (ho)
                a = a ^ 0x1b;
            b = ((b >> 1) & 0x7F);
        }
        return p;
    }

    public static void MultiplyMatrixByInvGalois(int[] column) {
        int[] columnCopy = new int[4];
        System.arraycopy(column, 0, columnCopy, 0, columnCopy.length);

        for (int i = 0; i < 4; i++) {
            int result = 0;
            for (int j = 0; j < 4; j++) {
                result ^= galoisMultiply((byte) invGaloisMatrix[i][j], (byte) columnCopy[j]);
            }
            column[i] = result;
        }
    }


}
