import java.util.Arrays;

import static util.KalynaConsts.*;

public class Kalyna {

    int nb;
    int nk;
    int nr;
    long[] state;
    long[][] roundKeys;

    long blockLength = 128;
    long keyLength = 128;

    Kalyna(long blockLength, long keyLength) {
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

        state = new long[nb];
        roundKeys = new long[nr + 1][nb];
    }

    private void subBytes() {
        long[] s = state;
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
        long[] s = wordsToBytes(nb, state);
        long[] ns = new long[nb];

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

    private long multiplyGF(long x, long y) {
        int r = 0;
        long hBit = 0;
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

    private void matrixMultiply(long[][] matrix) {
        int row, b;
        int product, result;
        long[] s = wordsToBytes(nb, state);
        for (int col = 0; col < nb; ++col) {
            result = 0;
            for (row = 7; row >= 0; --row) {
                product = 0;
                for (b = 7; b >= 0; --b) {
                    product ^= multiplyGF(s[b + col * 8], matrix[row][b]);
                }
                result |= product << (row * 8);
            }
            state[col] = result;
        }
    }

    private void mixColumns() {
        matrixMultiply(mds_matrix);
    }

    private void invMixColumns() {
        matrixMultiply(inv_mds_matrix);
    }

    private void encipherRound() {
        subBytes();
        shiftRows();
        mixColumns();
    }

    private void decipherRound() {
        invMixColumns();
        invShiftRows();
        insSubBytes();
    }

    private void addRoundKey(int round) {
        for (int i = 0; i < nb; ++i) {
            state[i] = state[i] + roundKeys[round][i];
        }
    }

    private void subRoundKey(int round) {
        for (int i = 0; i < nb; ++i) {
            state[i] = state[i] - roundKeys[round][i];
        }
    }

    private void xorRoundKey(int round) {
        for (int i = 0; i < nb; ++i) {
            state[i] = state[i] ^ roundKeys[round][i];
        }
    }

    private void addRoundKeyExpand(long[] value) {
        for (int i = 0; i < nb; ++i) {
            state[i] = state[i] + value[i];
        }
    }

    private void xorRoundKeyExpand(long[] value) {
        for (int i = 0; i < nb; ++i) {
            state[i] = state[i] ^ value[i];
        }
    }

    private void rotate(int state_size, long[] state_value) {
        int temp = state_value[0];
        for (int i = 1; i < state_size; ++i) {
            state_value[i - 1] = state_value[i];
        }
        state_value[state_size - 1] = temp;
    }

    private void shiftLeft(int state_size, long[] state_value) {
        for (int i = 0; i < state_size; ++i) {
            state_value[i] <<= 1;
        }
    }

    // ?
    private void rotateLeft(int state_size, int[] state_value) {
        int rotate_bytes = 2 * state_size + 3;
        int bytes_num = state_size * (kBITS_IN_WORD / kBITS_IN_BYTE);

        long[] bytes = wordsToBytes(state_size, state_value);

        long [] buffer = Arrays.copyOf(bytes, rotate_bytes);
        System.arraycopy(bytes, rotate_bytes, bytes, 0, bytes_num - rotate_bytes);
        System.arraycopy(buffer, 0, bytes, bytes_num - rotate_bytes, rotate_bytes);

        state_value = bytesToWords(bytes_num, bytes);
    }

    //?
    private long[] keyExpandKt(long[] key) {
        long[] k0;
        long[] k1 = new long[nb];
        Arrays.fill(state, 0);
        state[0] += nb + nk + 1;

        if (nb == nk) {
            k0 = Arrays.copyOf(key, nb);
            k1 = Arrays.copyOf(key, nb);
        } else {
            k0 = Arrays.copyOf(key, nb);
            System.arraycopy(key, nb, k1, 0, nb);
        }

        addRoundKeyExpand(k0);
        encipherRound();
        xorRoundKeyExpand(k1);
        encipherRound();
        addRoundKeyExpand(k0);
        encipherRound();

        return(Arrays.copyOf(state, nb));
    }

    private void keyExpandEven(long[] key, long[] kt) {
        long[] initial_data = new long[nk];
        long[] kt_round = new long[nb];
        long[] twv = new long[nb];
        int round = 0;

        initial_data = Arrays.copyOf(key, nk);
        for (int i = 0; i < nb; ++i) {
            twv[i] = 0x0001000100010001L;
        }

        while (true) {
            state = Arrays.copyOf(kt, nb);
            addRoundKeyExpand(twv);
            kt_round = Arrays.copyOf(state, nb);
            state = Arrays.copyOf(initial_data, nb);

            addRoundKeyExpand(kt_round);
            encipherRound();
            xorRoundKeyExpand(kt_round);
            encipherRound();
            addRoundKeyExpand(kt_round);

            roundKeys[round] = Arrays.copyOf(state, nb);

            if (nr == round) {
                break;
            }

            if (nk != nb) {
                round += 2;
                shiftLeft(nb, twv);
                state = Arrays.copyOf(kt, nb);
                addRoundKeyExpand(twv);
                kt_round = Arrays.copyOf(state, nb);
                System.arraycopy(initial_data, nb, state, 0, nb);

                addRoundKeyExpand(kt_round);
                encipherRound();
                xorRoundKeyExpand(kt_round);
                encipherRound();
                addRoundKeyExpand(kt_round);

                roundKeys[round] = Arrays.copyOf(state, nb);

                if (nr == round) {
                    break;
                }
            }
            round += 2;
            shiftLeft(nb, twv);
            rotate(nk, initial_data);
        }
    }





}
