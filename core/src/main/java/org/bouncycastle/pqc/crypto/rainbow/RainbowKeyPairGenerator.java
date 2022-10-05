package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowKeyComputation;

public class RainbowKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private RainbowKeyComputation rkc;

    private void initialize(KeyGenerationParameters param)
    {
        RainbowParameters rainbowParams = ((RainbowKeyGenerationParameters) param).getParameters();
        this.rkc = new RainbowKeyComputation(rainbowParams, param.getRandom());
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return this.rkc.genKeyPair();
    }
}
