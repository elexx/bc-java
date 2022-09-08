package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

import java.security.SecureRandom;
import java.util.Arrays;

public class RainbowKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private RainbowKeyGenerationParameters rainbowParams;
    ComputeInField cf = new ComputeInField();

    private int v1;
    private int o1;
    private int o2;

    private short[][] s1;
    private short[][] t1;
    private short[][] t2;
    private short[][] t3;
    private short[][] t4;
    private short[][][] l1_F1;
    private short[][][] l1_F2;
    private short[][][] l2_F1;
    private short[][][] l2_F2;
    private short[][][] l2_F3;
    private short[][][] l2_F5;
    private short[][][] l2_F6;

    private short[][][] l1_Q1;
    private short[][][] l1_Q2;
    private short[][][] l1_Q3;
    private short[][][] l1_Q5;
    private short[][][] l1_Q6;
    private short[][][] l1_Q9;
    private short[][][] l2_Q1;
    private short[][][] l2_Q2;
    private short[][][] l2_Q3;
    private short[][][] l2_Q5;
    private short[][][] l2_Q6;
    private short[][][] l2_Q9;

    private void initialize(KeyGenerationParameters param)
    {
        this.rainbowParams = (RainbowKeyGenerationParameters) param;
        this.random = param.getRandom();

        this.v1 = rainbowParams.getParameters().getV1();
        this.o1 = rainbowParams.getParameters().getO1();
        this.o2 = rainbowParams.getParameters().getO2();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        RainbowPrivateKeyParameters privKey;
        RainbowPublicKeyParameters pubKey;

        byte[] sk_seed = new byte[rainbowParams.getParameters().getLen_skseed()];
        random.nextBytes(sk_seed);

        byte[] pk_seed = new byte[rainbowParams.getParameters().getLen_pkseed()];
        random.nextBytes(pk_seed);

        SecureRandom sk_random = new SecureRandom(sk_seed);
        this.s1 = generate_random_2d(sk_random, o1, o2);
        this.t1 = generate_random_2d(sk_random, v1, o1);
        this.t2 = generate_random_2d(sk_random, v1, o2);
        this.t3 = generate_random_2d(sk_random, o1, o2);
        // t4 = t1 * t3 - t2
        calculate_t4();

        SecureRandom pk_random = new SecureRandom(pk_seed);
        // generating l1_Q1, l1_Q2, l2_Q1, l2_Q2, l2_Q3, l2_Q5, l2_Q6
        this.l1_Q1 = generate_random(pk_random, o1, v1, v1, true);
        this.l1_Q2 = generate_random(pk_random, o1, v1, o1, false);
        this.l2_Q1 = generate_random(pk_random, o2, v1, v1, true);
        this.l2_Q2 = generate_random(pk_random, o2, v1, o1, false);
        this.l2_Q3 = generate_random(pk_random, o2, v1, o2, false);
        this.l2_Q5 = generate_random(pk_random, o2, o1, o1, true);
        this.l2_Q6 = generate_random(pk_random, o2, o1, o2, false);
        this.l1_Q1 = cf.obfuscate_l1_polys(this.s1, this.l2_Q1, this.l1_Q1);
        this.l1_Q2 = cf.obfuscate_l1_polys(this.s1, this.l2_Q2, this.l1_Q2);
        // calculate the rest parts of secret key from Qs and S,T
        calculate_F_from_Q();
        // calculate the rest parts of public key: l1_Q3, l1_Q5, l1_Q6, l1_Q9, l2_Q9
        calculate_Q_from_F();
        this.l1_Q3 = cf.obfuscate_l1_polys(this.s1, this.l2_Q3, this.l1_Q3);
        this.l1_Q5 = cf.obfuscate_l1_polys(this.s1, this.l2_Q5, this.l1_Q5);
        this.l1_Q6 = cf.obfuscate_l1_polys(this.s1, this.l2_Q6, this.l1_Q6);
        this.l1_Q9 = cf.obfuscate_l1_polys(this.s1, this.l2_Q9, this.l1_Q9);

        privKey = new RainbowPrivateKeyParameters(  this.rainbowParams.getParameters(),
                                                    sk_seed, this.s1, this.t1, this.t3, this.t4,
                                                    this.l1_F1, this.l1_F2, this.l2_F1, this.l2_F2,
                                                    this.l2_F3, this.l2_F5, this.l2_F6);
        pubKey = new RainbowPublicKeyParameters(this.rainbowParams.getParameters(),
                                                pk_seed, this.l1_Q3, this.l1_Q5, this.l1_Q6, this.l1_Q9, this.l2_Q9);

        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    private short[][] generate_random_2d(SecureRandom sr, int dim_row, int dim_col)
    {
        short[][] matrix = new short[dim_row][dim_col];

        for (int i = 0; i < dim_row; i++)
        {
            for (int j = 0; j < dim_col; j++)
            {
                matrix[i][j] = (short) (sr.nextInt() & GF2Field.MASK);
            }
        }

        return matrix;
    }

    private short[][][] generate_random(SecureRandom sr, int dim_batch, int dim_row, int dim_col, boolean triangular)
    {
        short[][][] matrix = new short[dim_batch][dim_row][dim_col];

        for (int k = 0; k < dim_batch; k++)
        {
            for (int i = 0; i < dim_row; i++)
            {
                for (int j = (triangular ? i : 0); j < dim_col; j++)
                {
                    matrix[k][i][j] = (short) (sr.nextInt() & GF2Field.MASK);
                }
            }
        }
        return matrix;
    }

    // t4 = t1 * t3 -t2
    private void calculate_t4()
    {
        short[][] temp = cf.multiplyMatrix(this.t1, this.t3);
        this.t4 = cf.addMatrix(temp, this.t2);
    }



    private void calculate_F_from_Q()
    {
        // Layer 1
        // F1 = Q1
        this.l1_F1 = RainbowUtil.cloneArray(this.l1_Q1);

        // F2 = (Q1 + Q1_trans) * T1 + Q2
        this.l1_F2 = new short[this.o1][][];
        for (int k = 0; k < this.o1; k++)
        {
            this.l1_F2[k] = cf.addMatrixTranspose(this.l1_Q1[k]);
            this.l1_F2[k] = cf.multiplyMatrix(this.l1_F2[k], this.t1);
            this.l1_F2[k] = cf.addMatrix(this.l1_F2[k], this.l1_Q2[k]);
        }

        // Layer 2
        this.l2_F2 = new short[this.o2][][];
        this.l2_F3 = new short[this.o2][][];
        this.l2_F5 = new short[this.o2][][];
        this.l2_F6 = new short[this.o2][][];

        // F1 = Q1
        this.l2_F1 = RainbowUtil.cloneArray(this.l2_Q1);

        // F2 = (Q1 + Q1_trans) * T1 + Q2
        for (int k = 0; k < this.o2; k++)
        {
            short[][] Q1Q1_t = cf.addMatrixTranspose(this.l2_Q1[k]);
            this.l2_F2[k] = cf.multiplyMatrix(Q1Q1_t, this.t1);
            this.l2_F2[k] = cf.addMatrix(this.l2_F2[k], this.l2_Q2[k]);

            // F3 = (Q1 + Q1_trans) * T4 + Q2 * T3 + Q3
            this.l2_F3[k] = cf.multiplyMatrix(Q1Q1_t, this.t4);
            short[][] temp = cf.multiplyMatrix(this.l2_Q2[k], this.t3);
            this.l2_F3[k] = cf.addMatrix(this.l2_F3[k], temp);
            this.l2_F3[k] = cf.addMatrix(this.l2_F3[k], this.l2_Q3[k]);

            // F5 = UT( T1_trans * Q1 * T1 + T1_trans * Q2 + Q5)
            temp = cf.multiplyMatrix(this.l2_Q1[k], this.t1);
            temp = cf.addMatrix(temp, this.l2_Q2[k]);
            short[][] T1_trans = cf.transpose(this.t1);
            this.l2_F5[k] = cf.multiplyMatrix(T1_trans, temp);
            this.l2_F5[k] = cf.addMatrix(this.l2_F5[k], this.l2_Q5[k]);
            this.l2_F5[k] = cf.to_UT(this.l2_F5[k]);

            // F6 = T1_trans * (Q1 + Q1_trans) * T4 + T1_trans * Q2 * T3 + T1_trans * Q3 + Q2_trans * T4 + (Q5 + Q5_trans) * T3 + Q6
            //    = T1_trans * F3 + Q2_trans * T4 + (Q5 + Q5_trans) * T3 + Q6
            this.l2_F6[k] = cf.multiplyMatrix(T1_trans, this.l2_F3[k]);
            temp = cf.multiplyMatrix(cf.transpose(this.l2_Q2[k]), this.t4);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], temp);
            temp = cf.addMatrixTranspose(this.l2_Q5[k]);
            temp = cf.multiplyMatrix(temp, this.t3);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], temp);
            this.l2_F6[k] = cf.addMatrix(this.l2_F6[k], this.l2_Q6[k]);
        }
    }

    private void calculate_Q_from_F()
    {
        short[][] T1_trans = cf.transpose(this.t1);
        short[][] T2_trans = cf.transpose(this.t2);

        // Layer 1
        this.l1_Q3 = new short[this.o1][][];
        this.l1_Q5 = new short[this.o1][][];
        this.l1_Q6 = new short[this.o1][][];
        this.l1_Q9 = new short[this.o1][][];

        for (int k = 0; k < this.o1; k++)
        {
            // Q3 = (F1 + F1_trans) * T2 + F2 * T3
            short[][] F2T3 = cf.multiplyMatrix(this.l1_F2[k], this.t3);
            this.l1_Q3[k] = cf.addMatrixTranspose(this.l1_F1[k]);
            this.l1_Q3[k] = cf.multiplyMatrix(this.l1_Q3[k], this.t2);
            this.l1_Q3[k] = cf.addMatrix(this.l1_Q3[k], F2T3);

            // Q5 = UT( T1_trans * (F1 * T1 + F2))
            this.l1_Q5[k] = cf.multiplyMatrix(this.l1_F1[k], this.t1);
            this.l1_Q5[k] = cf.addMatrix(this.l1_Q5[k], this.l1_F2[k]);
            this.l1_Q5[k] = cf.multiplyMatrix(T1_trans, this.l1_Q5[k]);
            this.l1_Q5[k] = cf.to_UT(this.l1_Q5[k]);

            // Q6 = T1_trans * (F1 + F1_trans) * T2 + T1_trans * F2 * T3 + F2_trans * T2
            //    = T1_trans * Q3 + F2_trans * T2
            short[][] temp = cf.multiplyMatrix(cf.transpose(this.l1_F2[k]), this.t2);
            this.l1_Q6[k] = cf.multiplyMatrix(T1_trans, this.l1_Q3[k]);
            this.l1_Q6[k] = cf.addMatrix(this.l1_Q6[k], temp);

            // Q9 = UT( T2_trans * (F1 * T2 + F2 * T3))
            temp = cf.multiplyMatrix(this.l1_F1[k], this.t2);
            this.l1_Q9[k] = cf.addMatrix(temp, F2T3);
            this.l1_Q9[k] = cf.multiplyMatrix(T2_trans, this.l1_Q9[k]);
            this.l1_Q9[k] = cf.to_UT(this.l1_Q9[k]);
        }

        // Layer 2
        this.l2_Q9 = new short[this.o2][][];

        for (int k = 0; k < this.o2; k++)
        {
            // Q9 = UT( T2_trans * (F1 * T2 + F2 * T3 + F3) + T3_trans * ( F5 * T3 + F6))
            this.l2_Q9[k] = cf.multiplyMatrix(this.l2_F1[k], this.t2);
            short[][] temp = cf.multiplyMatrix(this.l2_F2[k], this.t3);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], temp);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], this.l2_F3[k]);
            this.l2_Q9[k] = cf.multiplyMatrix(T2_trans, this.l2_Q9[k]);
            temp = cf.multiplyMatrix(this.l2_F5[k], this.t3);
            temp = cf.addMatrix(temp, this.l2_F6[k]);
            temp = cf.multiplyMatrix(cf.transpose(this.t3), temp);
            this.l2_Q9[k] = cf.addMatrix(this.l2_Q9[k], temp);
            this.l2_Q9[k] = cf.to_UT(this.l2_Q9[k]);
        }
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair() { return genKeyPair(); }
}
