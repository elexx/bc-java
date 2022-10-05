package org.bouncycastle.pqc.crypto.rainbow;

public class RainbowPublicKeyParameters
        extends RainbowKeyParameters
{
    private short[][][] pk;

    public RainbowPublicKeyParameters(RainbowParameters params,
                                      short[][][] l1_Q1, short[][][] l1_Q2, short[][][] l1_Q3,
                                      short[][][] l1_Q5, short[][][] l1_Q6, short[][][] l1_Q9,
                                      short[][][] l2_Q1, short[][][] l2_Q2, short[][][] l2_Q3,
                                      short[][][] l2_Q5, short[][][] l2_Q6, short[][][] l2_Q9)
    {
        super(false, params);

        int v1 = params.getV1();
        int o1 = params.getO1();
        int o2 = params.getO2();

        pk = new short[params.getM()][params.getN()][params.getN()];
        for (int k = 0; k < o1; k++)
        {
            for (int i = 0; i < v1; i++)
            {
                System.arraycopy(l1_Q1[k][i], 0, pk[k][i], 0, v1);
                System.arraycopy(l1_Q2[k][i], 0, pk[k][i], v1, o1);
                System.arraycopy(l1_Q3[k][i], 0, pk[k][i], v1+o1, o2);
            }
            for (int i = 0; i < o1; i++)
            {
                System.arraycopy(l1_Q5[k][i], 0, pk[k][i + v1], v1, o1);
                System.arraycopy(l1_Q6[k][i], 0, pk[k][i + v1], v1+o1, o2);
            }
            for (int i = 0; i < o2; i++)
            {
                System.arraycopy(l1_Q9[k][i], 0, pk[k][i + v1 + o1], v1+o1, o2);
            }
        }
        for (int k = 0; k < o2; k++)
        {
            for (int i = 0; i < v1; i++)
            {
                System.arraycopy(l2_Q1[k][i], 0, pk[k + o1][i], 0, v1);
                System.arraycopy(l2_Q2[k][i], 0, pk[k + o1][i], v1, o1);
                System.arraycopy(l2_Q3[k][i], 0, pk[k + o1][i], v1+o1, o2);
            }
            for (int i = 0; i < o1; i++)
            {
                System.arraycopy(l2_Q5[k][i], 0, pk[k + o1][i + v1], v1, o1);
                System.arraycopy(l2_Q6[k][i], 0, pk[k + o1][i + v1], v1+o1, o2);
            }
            for (int i = 0; i < o2; i++)
            {
                System.arraycopy(l2_Q9[k][i], 0, pk[k + o1][i + v1 + o1], v1+o1, o2);
            }
        }
    }

    public short[][][] getPk()
    {
        return pk;
    }
}
