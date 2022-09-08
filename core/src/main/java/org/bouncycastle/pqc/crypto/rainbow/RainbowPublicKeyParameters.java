package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{

    private byte[] pk_seed;
    private short[][][] l1_Q3;
    private short[][][] l1_Q5;
    private short[][][] l1_Q6;
    private short[][][] l1_Q9;
    private short[][][] l2_Q9;

    public RainbowPublicKeyParameters(  RainbowParameters params,
                                        byte[] pk_seed,
                                        short[][][] l1_Q3, short[][][] l1_Q5,
                                        short[][][] l1_Q6, short[][][] l1_Q9,
                                        short[][][] l2_Q9)
    {
        super(false, params);

        this.pk_seed = pk_seed.clone();
        this.l1_Q3 = RainbowUtil.cloneArray(l1_Q3);
        this.l1_Q5 = RainbowUtil.cloneArray(l1_Q5);
        this.l1_Q6 = RainbowUtil.cloneArray(l1_Q6);
        this.l1_Q9 = RainbowUtil.cloneArray(l1_Q9);
        this.l2_Q9 = RainbowUtil.cloneArray(l2_Q9);
    }

    public byte[] getPk_seed()
    {
        return pk_seed;
    }

    public short[][][] getL1_Q3()
    {
        return l1_Q3;
    }

    public short[][][] getL1_Q5()
    {
        return l1_Q5;
    }

    public short[][][] getL1_Q6()
    {
        return l1_Q6;
    }

    public short[][][] getL1_Q9()
    {
        return l1_Q9;
    }

    public short[][][] getL2_Q9()
    {
        return l2_Q9;
    }
}
