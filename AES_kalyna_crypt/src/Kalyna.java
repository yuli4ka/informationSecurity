import java.util.ArrayList;
import java.util.Arrays;

import static util.KalynaConsts.*;
import static util.SBoxes.*;
import static util.Utils.printMatrix;

public class Kalyna {

    int nb;
    int nk;
    int nr;
    int[] state;
    int[][] roundKeys;

    int blockLength = 128;
    int keyLength = 128;

    Kalyna(int blockLength, int keyLength) {
        if (blockLength == kBLOCK_128) {
            nb = kBLOCK_128 / kBITS_IN_WORD;
            if (keyLength == kKEY_128) {
                nk = kKEY_128 / kBITS_IN_WORD;
                nr = kNR_128;
            } else if (keyLength == kKEY_256) {
                nk = kKEY_256 / kBITS_IN_WORD;
                nr = kNR_256;
            } else if (keyLength == kKEY_512) {
                nk = kKEY_512 / kBITS_IN_WORD;
                nr = kNR_512;
            } else {
                return;
            }
        } else if (blockLength == kBLOCK_256) {
            nb = kBLOCK_256 / kBITS_IN_WORD;
            if (keyLength == kKEY_256) {
                nk = kKEY_256 / kBITS_IN_WORD;
                nr = kNR_256;
            } else if (keyLength == kKEY_512) {
                nk = kKEY_512 / kBITS_IN_WORD;
                nr = kNR_512;
            } else {
                return;
            }
        } else if (blockLength == kBLOCK_512) {
            nb = kBLOCK_512 / kBITS_IN_WORD;
            if (keyLength == kKEY_512) {
                nk = kKEY_512 / kBITS_IN_WORD;
                nr = kNR_512;
            } else {
                return;
            }
        } else {
            return;
        }

        state = new int[nb];
        roundKeys = new int[nr + 1][nb];
    }

    private void subBytes() {
        int[] s = state;
        for (int i = 0; i < nb; ++i) {
            state[i] = sBOXES_ENC[0][(int) (s[i] & 0x00000000000000FFL)] |
                    (sBOXES_ENC[1][(int) ((s[i] & 0x000000000000FF00L) >> 8)] << 8) |
                    (sBOXES_ENC[2][(int) ((s[i] & 0x0000000000FF0000L) >> 16)] << 16) |
                    (sBOXES_ENC[3][(int) ((s[i] & 0x00000000FF000000L) >> 24)] << 24) |
                    (sBOXES_ENC[0][(int) ((s[i] & 0x000000FF00000000L) >> 32)] << 32) |
                    (sBOXES_ENC[1][(int) ((s[i] & 0x0000FF0000000000L) >> 40)] << 40) |
                    (sBOXES_ENC[2][(int) ((s[i] & 0x00FF000000000000L) >> 48)] << 48) |
                    (sBOXES_ENC[3][(int) ((s[i] & 0xFF00000000000000L) >> 56)] << 56);
        }
    }

    private void insSubBytes() {
        int[] s = state;
        for (int i = 0; i < nb; ++i) {
            state[i] = sBOXES_DEC[0][(int) (s[i] & 0x00000000000000FFL)] |
                    (sBOXES_DEC[1][(int) ((s[i] & 0x000000000000FF00L) >> 8)] << 8) |
                    (sBOXES_DEC[2][(int) ((s[i] & 0x0000000000FF0000L) >> 16)] << 16) |
                    (sBOXES_DEC[3][(int) ((s[i] & 0x00000000FF000000L) >> 24)] << 24) |
                    (sBOXES_DEC[0][(int) ((s[i] & 0x000000FF00000000L) >> 32)] << 32) |
                    (sBOXES_DEC[1][(int) ((s[i] & 0x0000FF0000000000L) >> 40)] << 40) |
                    (sBOXES_DEC[2][(int) ((s[i] & 0x00FF000000000000L) >> 48)] << 48) |
                    (sBOXES_DEC[3][(int) ((s[i] & 0xFF00000000000000L) >> 56)] << 56);
        }
    }

    private void shiftRows() {
        int shift = -1;
        int[] s = wordsToBytes(nb, state);
        int[] ns = new int[nb];

        for (int row = 0; row < 8; ++row) {
            if (row % (8 / nb) == 0) {
                shift += 1;
            }
            for (int col = 0; col < nb; ++col) {
                ns[row + ((col + shift) % nb) * 8] = s[row + col * 8];
            }
        }
        state = bytesToWords(nb * 8, ns);
    }

    private void invShiftRows() {
        int shift = -1;
        int[] s = wordsToBytes(nb, state);
        int[] ns = new int[nb];

        for (int row = 0; row < 8; ++row) {
            if (row % (8 / nb) == 0) {
                shift += 1;
            }
            for (int col = 0; col < nb; ++col) {
                ns[row + col * 8] = s[row + ((col + shift) % nb) * 8];
            }
        }
        state = bytesToWords(nb * 8, ns);
    }

    private int multiplyGF(int x, int y) {
        int r = 0;
        int hBit = 0;
        for (int i = 0; i < kBITS_IN_BYTE; ++i) {
            if ((y & 0x1) == 1) {
                r ^= x;
            }
            hBit = x & 0x80;
            x <<= 1;
            if (hBit == 0x80) {
                x ^= kREDUCTION_POLYNOMIAL;
            }
            y >>= 1;
        }
        return r;
    }

    private void matrixMultiply(int[][] matrix) {
        int row, b;
        int product, result;
        int[] s = wordsToBytes(nb, state);
        for (int col = 0; col < nb; ++col) {
            result = 0;
            for (row = 7; row >= 0; --row) {
                product = 0;
                for (b = 7; b >= 0; --b) {
                    product ^= multiplyGF(state[b + col * 8], matrix[row][b]);
                }
                result |= product << (row * 8);
            }
            state[col] = result;
        }
    }



}
