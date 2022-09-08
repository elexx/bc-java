package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

import java.util.Arrays;

public class RainbowPrivateKeyParameters
    extends RainbowKeyParameters
{
    private final byte[] sk_seed;
    private final short[][] s1;
    private final short[][] t1;
    private final short[][] t3;
    private final short[][] t4;
    private final short[][][] l1_F1;
    private final short[][][] l1_F2;
    private final short[][][] l2_F1;
    private final short[][][] l2_F2;
    private final short[][][] l2_F3;
    private final short[][][] l2_F5;
    private final short[][][] l2_F6;

    public RainbowPrivateKeyParameters( RainbowParameters params,
                                        byte[] sk_seed, short[][] s1,
                                        short[][] t1, short[][] t3, short[][] t4,
                                        short[][][] l1_F1, short[][][] l1_F2,
                                        short[][][] l2_F1, short[][][] l2_F2,
                                        short[][][] l2_F3, short[][][] l2_F5, short[][][] l2_F6)
    {
        super(true, params);

        this.sk_seed = sk_seed.clone();
        this.s1 = Arrays.stream(s1).map(short[]::clone).toArray(short[][]::new);
        this.t1 = Arrays.stream(t1).map(short[]::clone).toArray(short[][]::new);
        this.t3 = Arrays.stream(t3).map(short[]::clone).toArray(short[][]::new);
        this.t4 = Arrays.stream(t4).map(short[]::clone).toArray(short[][]::new);
        this.l1_F1 = RainbowUtil.cloneArray(l1_F1);
        this.l1_F2 = RainbowUtil.cloneArray(l1_F2);
        this.l2_F1 = RainbowUtil.cloneArray(l2_F1);
        this.l2_F2 = RainbowUtil.cloneArray(l2_F2);
        this.l2_F3 = RainbowUtil.cloneArray(l2_F3);
        this.l2_F5 = RainbowUtil.cloneArray(l2_F5);
        this.l2_F6 = RainbowUtil.cloneArray(l2_F6);
    }

    public byte[] getSk_seed()
    {
        return sk_seed;
    }

    public short[][] getS1()
    {
        return s1;
    }

    public short[][] getT1()
    {
        return t1;
    }

    public short[][] getT4()
    {
        return t4;
    }

    public short[][] getT3()
    {
        return t3;
    }

    public short[][][] getL1_F1()
    {
        return l1_F1;
    }

    public short[][][] getL1_F2()
    {
        return l1_F2;
    }

    public short[][][] getL2_F1()
    {
        return l2_F1;
    }

    public short[][][] getL2_F2()
    {
        return l2_F2;
    }

    public short[][][] getL2_F3()
    {
        return l2_F3;
    }

    public short[][][] getL2_F5()
    {
        return l2_F5;
    }

    public short[][][] getL2_F6()
    {
        return l2_F6;
    }
}
