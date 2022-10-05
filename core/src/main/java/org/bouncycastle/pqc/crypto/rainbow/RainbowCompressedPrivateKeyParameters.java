package org.bouncycastle.pqc.crypto.rainbow;

public class RainbowCompressedPrivateKeyParameters
        extends RainbowKeyParameters
{
    private byte[] sk_seed;
    private byte[] pk_seed;

    public RainbowCompressedPrivateKeyParameters(RainbowParameters params, byte[] sk_seed, byte[] pk_seed)
    {
        super(true, params);
        this.sk_seed = sk_seed.clone();
        this.pk_seed = pk_seed.clone();
    }

    public byte[] getSk_seed()
    {
        return sk_seed;
    }

    public byte[] getPk_seed()
    {
        return pk_seed;
    }
}
