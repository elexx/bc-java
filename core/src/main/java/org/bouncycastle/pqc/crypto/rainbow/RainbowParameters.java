package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public class RainbowParameters
    implements CipherParameters
{

    private final int v1;
    private final int v2;
    private final int o1;
    private final int o2;
    private final int n;
    private final int m;
    private static final int len_pkseed = 32;
    private static final int len_skseed = 32;
    private static final int len_salt = 16;
    private final Digest hash_algo;
    private final Version version;

    public RainbowParameters(int strength, Version version)
    {
        switch (strength)
        {
            case 3:
                this.v1 = 68;
                this.o1 = 32;
                this.o2 = 48;
                this.hash_algo = new SHA384Digest();
                break;
            case 5:
                this.v1 = 96;
                this.o1 = 36;
                this.o2 = 64;
                this.hash_algo = new SHA512Digest();
                break;
            default:
                throw new IllegalArgumentException(
                        "No valid version. Please choose one of the following: 3, 5");
        }

        this.v2 = v1 + o1;
        this.n = v1 + o1 + o2;
        this.m = o1 + o2;
        this.version = version;
    }

    public RainbowParameters()
    {
        // TODO: choose default version
        this(3, Version.CLASSIC);
    }

    public int getV1()
    {
        return this.v1;
    }

    public int getO1()
    {
        return this.o1;
    }

    public int getO2()
    {
        return this.o2;
    }

    public Digest getHash_algo()
    {
        return this.hash_algo;
    }

    public Version getVersion()
    {
        return this.version;
    }

    public int getV2()
    {
        return v2;
    }

    public int getN()
    {
        return n;
    }

    public int getM()
    {
        return m;
    }

    public int getLen_pkseed()
    {
        return len_pkseed;
    }

    public int getLen_skseed()
    {
        return len_skseed;
    }

    public int getLen_salt()
    {
        return len_salt;
    }

}
