package org.bouncycastle.pqc.crypto.rainbow.util;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class is needed for the conversions while encoding and decoding, as well as for
 * comparison between arrays of some dimensions
 */
public class RainbowUtil
{

    /**
     * This function converts an one-dimensional array of bytes into a
     * one-dimensional array of int
     *
     * @param in the array to be converted
     * @return out
     *         the one-dimensional int-array that corresponds the input
     */
    public static int[] convertArraytoInt(byte[] in)
    {
        int[] out = new int[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = in[i] & GF2Field.MASK;
        }
        return out;
    }

    /**
     * This function converts an one-dimensional array of bytes into a
     * one-dimensional array of type short
     *
     * @param in the array to be converted
     * @return out
     *         one-dimensional short-array that corresponds the input
     */
    public static short[] convertArray(byte[] in)
    {
        short[] out = new short[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (short)(in[i] & GF2Field.MASK);
        }
        return out;
    }

    /**
     * This function converts a matrix of bytes into a matrix of type short
     *
     * @param in the matrix to be converted
     * @return out
     *         short-matrix that corresponds the input
     */
    public static short[][] convertArray(byte[][] in)
    {
        short[][] out = new short[in.length][in[0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                out[i][j] = (short)(in[i][j] & GF2Field.MASK);
            }
        }
        return out;
    }

    /**
     * This function converts a 3-dimensional array of bytes into a 3-dimensional array of type short
     *
     * @param in the array to be converted
     * @return out
     *         short-array that corresponds the input
     */
    public static short[][][] convertArray(byte[][][] in)
    {
        short[][][] out = new short[in.length][in[0].length][in[0][0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                for (int k = 0; k < in[0][0].length; k++)
                {
                    out[i][j][k] = (short)(in[i][j][k] & GF2Field.MASK);
                }
            }
        }
        return out;
    }

    /**
     * This function converts an array of type int into an array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[] convertIntArray(int[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)in[i];
        }
        return out;
    }


    /**
     * This function converts an array of type short into an array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[] convertArray(short[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)in[i];
        }
        return out;
    }

    /**
     * This function converts a matrix of type short into a matrix of type byte
     *
     * @param in the matrix to be converted
     * @return out
     *         the byte-matrix that corresponds the input
     */
    public static byte[][] convertArray(short[][] in)
    {
        byte[][] out = new byte[in.length][in[0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                out[i][j] = (byte)in[i][j];
            }
        }
        return out;
    }

    /**
     * This function converts a 3-dimensional array of type short into a 3-dimensional array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[][][] convertArray(short[][][] in)
    {
        byte[][][] out = new byte[in.length][in[0].length][in[0][0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                for (int k = 0; k < in[0][0].length; k++)
                {
                    out[i][j][k] = (byte)in[i][j][k];
                }
            }
        }
        return out;
    }

    /**
     * Compare two short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[] left, short[] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= left[i] == right[i];
        }
        return result;
    }

    /**
     * Compare two two-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][] left, short[][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

    /**
     * Compare two three-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][][] left, short[][][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

    public static short[][][] cloneArray(short[][][] toCopy)
    {
        short[][][] local = new short[toCopy.length][toCopy[0].length][];
        for (int i = 0; i < toCopy.length; i++)
        {
            for (int j = 0; j < toCopy[0].length; j++)
            {
                local[i][j] = Arrays.clone(toCopy[i][j]);
            }
        }
        return local;
    }

    public static byte[] hash(Digest hashAlgo, byte[] msg, int hash_length)
    {
        int digest_size = hashAlgo.getDigestSize();
        // final_hash = hash(msg) || hash(hash(msg)) || ...
        byte[] final_hash;

        // initial hash of msg
        hashAlgo.update(msg, 0, msg.length);
        byte[] hash = new byte[digest_size];
        hashAlgo.doFinal(hash, 0);

        // check if truncation is needed
        if (hash_length <= digest_size)
        {
            return Arrays.copyOf(hash, hash_length);
        }
        else
        {
            final_hash = Arrays.copyOf(hash, digest_size);
        }

        // compute expansion while needed
        int left_to_hash = hash_length - digest_size;
        while (left_to_hash >= hash_length)
        {
            hashAlgo.update(hash, 0, digest_size);
            hash = new byte[digest_size];
            hashAlgo.doFinal(hash, 0);
            final_hash = Arrays.concatenate(final_hash, hash);
            left_to_hash -= digest_size;
        }

        // check if final expansion is needed
        if (left_to_hash > 0)
        {
            hashAlgo.update(hash, 0, digest_size);
            hash = new byte[digest_size];
            hashAlgo.doFinal(hash, 0);
            int current_length = final_hash.length;
            final_hash = Arrays.copyOf(final_hash, current_length+left_to_hash);
            System.arraycopy(hash, 0, final_hash, current_length, left_to_hash);
        }

        return final_hash;
    }

    public static SecureRandom getSecureRandom(String algorithm, byte[] seed)
    {
        SecureRandom sr;
        try
        {
            sr = SecureRandom.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        sr.setSeed(seed);
        return sr;
    }

    public static short[][] generate_random_2d(SecureRandom sr, int dim_row, int dim_col)
    {
        short[][] matrix = new short[dim_row][dim_col];

        for (int i = 0; i < dim_row; i++)
        {
            for (int j = 0; j < dim_col; j++)
            {
                matrix[i][j] = (short) ((sr.nextInt() & GF2Field.MASK));
            }
        }

        return matrix;
    }

    public static short[][][] generate_random(SecureRandom sr, int dim_batch, int dim_row, int dim_col, boolean triangular)
    {
        short[][][] matrix = new short[dim_batch][dim_row][dim_col];

        for (int k = 0; k < dim_batch; k++)
        {
            for (int i = 0; i < dim_row; i++)
            {
                for (int j = (triangular ? i : 0); j < dim_col; j++)
                {
                    matrix[k][i][j] = (short) ((sr.nextInt() & GF2Field.MASK));
                }
            }
        }
        return matrix;
    }
/*
    public static void printArray(String s, short[][] a)
    {
        System.out.println(s);
        System.out.println(java.util.Arrays.deepToString(a));
    }

    public static void printArray(String s, short[][][] a)
    {
        System.out.println(s);
        for (short[][] shorts : a)
        {
            printArray("", shorts);
        }
    }
*/
}
