package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;

public class RainbowSigner
    implements MessageSigner
{
    private static final int MAXITS = 65536;

    // Source of randomness
    private SecureRandom random;

    // The length of a document that can be signed with the privKey
    int signableDocumentLength;

    private ComputeInField cf = new ComputeInField();

    RainbowKeyParameters key;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (RainbowPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                this.random = CryptoServicesRegistrar.getSecureRandom();
                this.key = (RainbowPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (RainbowPublicKeyParameters)param;
        }

        this.signableDocumentLength = this.key.getDocLength();
    }

    public byte[] generateSignature(byte[] message)
    {
        int v1 = this.key.getParams().getV1();
        int o1 = this.key.getParams().getO1();
        int o2 = this.key.getParams().getO2();
        int m  = this.key.getParams().getM(); // o1 + o2
        int n  = this.key.getParams().getN(); // o1 + o2 + v1

        RainbowPrivateKeyParameters sk = (RainbowPrivateKeyParameters)this.key;
        Digest hashAlgo = sk.getParams().getHash_algo();

        short[] vinegar = new short[v1];
        short[][] L1 = null; // layer 1 linear equations

        short[][] L2 = new short[o2][o2]; // layer 2 linear equations
        short[] r_l1_F1 = new short[o1];
        short[] r_l2_F1 = new short[o2];
        short[] r_l2_F5 = new short[o2];
        short[][] L2_F2 = new short[o2][o1];
        short[][] L2_F3 = new short[o2][o2];

        byte[] salt = new byte[sk.getParams().getLen_salt()];
        byte[] digest_salt;
        byte[] hash;
        short[] h;

        // x = S^1 * h
        short[] x = new short[m];

        // y = F^-1 * x
        short[] y_o1 = new short[o1];
        short[] y_o2 = null;

        // z = T^-1 * y
        short[] z;

        short temp;
        short[] tmp_vec;
        int counter = 0;

        while(L1 == null && counter < MAXITS)
        {
            for (int i = 0; i < v1; i++)
            {
                vinegar[i] = (short) (this.random.nextInt() & GF2Field.MASK);
            }
            L1 = new short[o1][o1];
            for (int i = 0; i < v1; i++)
            {
                for (int k = 0; k < o1; k++)
                {
                    for (int j = 0; j < o1; j++)
                    {
                        temp = GF2Field.multElem(sk.getL1_F2()[k][i][j], vinegar[i]);
                        L1[k][j] = GF2Field.addElem(L1[k][j], temp);
                    }
                }
            }
            L1 = cf.inverse(L1);
            counter++;
        }

        while (y_o2 == null && counter < MAXITS)
        {
            for (int k = 0; k < o1; k++)
            {
                r_l1_F1[k] = cf.multiplyMatrix_quad(sk.getL1_F1()[k], vinegar);
            }

            for (int k = 0; k < o2; k++)
            {
                r_l2_F1[k] = cf.multiplyMatrix_quad(sk.getL2_F1()[k], vinegar);
            }

            for (int i = 0; i < v1; i++)
            {
                for (int k = 0; k < o2; k++)
                {
                    for (int j = 0; j < o1; j++)
                    {
                        temp = GF2Field.multElem(sk.getL2_F2()[k][i][j], vinegar[i]);
                        L2_F2[k][j] = GF2Field.addElem(L2_F2[k][j], temp);
                    }
                }
            }

            for (int i = 0; i < v1; i++)
            {
                for (int k = 0; k < o2; k++)
                {
                    for (int j = 0; j < o2; j++)
                    {
                        temp = GF2Field.multElem(sk.getL2_F3()[k][i][j], vinegar[i]);
                        L2_F3[k][j] = GF2Field.addElem(L2_F3[k][j], temp);
                    }
                }
            }

            this.random.nextBytes(salt);
            digest_salt = Arrays.concatenate(message, salt);

            // h = (short)H(msg_digest||salt)
            hash = RainbowUtil.hash(hashAlgo, digest_salt, m);
            h = makeMessageRepresentative(hash);

            // x = S^-1 * h
            tmp_vec = cf.multiplyMatrix(sk.getS1(), Arrays.copyOfRange(h, o1, m));
            tmp_vec = cf.addVect(Arrays.copyOf(h, o1), tmp_vec);
            System.arraycopy(tmp_vec, 0, x, 0, o1);
            System.arraycopy(h, o1, x, o1, o2);  // identity part of S

            // y = F^-1 * x
            // layer 1: calculate y_o1
            tmp_vec = cf.addVect(r_l1_F1, Arrays.copyOf(x, o1));
            y_o1 = cf.multiplyMatrix(L1, tmp_vec);

            // layer 2: calculate y_o2
            tmp_vec = cf.multiplyMatrix(L2_F2, y_o1);
            for (int k = 0; k < o2; k++)
            {
                r_l2_F5[k] = cf.multiplyMatrix_quad(sk.getL2_F5()[k], y_o1);
            }
            tmp_vec = cf.addVect(tmp_vec, r_l2_F5);
            tmp_vec = cf.addVect(tmp_vec, r_l2_F1);
            tmp_vec = cf.addVect(tmp_vec, Arrays.copyOfRange(x, o1, m));

            for (int i = 0; i < o1; i++)
            {
                for (int k = 0; k < o2; k++)
                {
                    for (int j = 0; j < o2; j++)
                    {
                        temp = GF2Field.multElem(sk.getL2_F6()[k][i][j], y_o1[i]);
                        L2[k][j] = GF2Field.addElem(L2[k][j], temp);
                    }
                }
            }
            L2 = cf.addMatrix(L2, L2_F3);

            // y_o2 = null if LES not solvable - try again
            y_o2 = cf.solveEquation(L2, tmp_vec);

            counter++;
        }

        // continue even though LES wasn't solvable for time consistency
        y_o2 = (y_o2 == null) ? new short[o2] : y_o2;

        // z = T^-1 * y
        tmp_vec = cf.multiplyMatrix(sk.getT1(), y_o1);
        z = cf.addVect(vinegar, tmp_vec);
        tmp_vec = cf.multiplyMatrix(sk.getT4(), y_o2 );
        z = cf.addVect(z, tmp_vec);
        tmp_vec = cf.multiplyMatrix(sk.getT3(), y_o2);
        tmp_vec = cf.addVect(y_o1, tmp_vec);
        z = Arrays.copyOf(z, n);
        System.arraycopy(tmp_vec, 0, z, v1, o1);
        System.arraycopy(y_o2, 0, z, o1+v1, o2); // identity part of T

        if (counter == MAXITS)
        {
            throw new IllegalStateException("unable to generate signature - LES not solvable");
        }

        // cast signature from short[] to byte[]
        byte[] signature = new byte[n];
        for (int i = 0; i < n; i++)
        {
            signature[i] = ((byte)z[i]);
        }

        return Arrays.concatenate(signature, salt);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
    }

    /**
     * This function creates the representative of the message which gets signed
     * or verified.
     *
     * @param message the message
     * @return message representative
     */
    private short[] makeMessageRepresentative(byte[] message)
    {
        // the message representative
        short[] output = new short[this.signableDocumentLength];

        int h = 0;
        int i = 0;
        do
        {
            if (i >= message.length)
            {
                break;
            }
            output[i] = (short)message[h];
            output[i] &= (short)0xff;
            h++;
            i++;
        }
        while (i < output.length);

        return output;
    }
}
