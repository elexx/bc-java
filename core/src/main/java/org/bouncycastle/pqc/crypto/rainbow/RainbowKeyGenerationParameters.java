package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class RainbowKeyGenerationParameters
    extends KeyGenerationParameters
{
    private RainbowParameters params;

    public RainbowKeyGenerationParameters(
            SecureRandom random,
            RainbowParameters params
    )
    {

        // TODO: actual strength
        super(random, 256);
        this.params = params;
    }

    public RainbowParameters getParameters()
    {
        return params;
    }
}

