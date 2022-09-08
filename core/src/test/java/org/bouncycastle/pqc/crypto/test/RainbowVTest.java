package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class RainbowVTest
    extends SimpleTest
{
    public String getName()
    {
        return "Rainbow_V";
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters(5);

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(new SecureRandom(), params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), new SecureRandom());

        DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner(), params.getHash_algo());

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        rainbowSigner.update(message, 0, message.length);
        byte[] sig = rainbowSigner.generateSignature();

        System.out.println(Arrays.toString(sig));

        /*
        rainbowSigner.init(false, pair.getPublic());
        rainbowSigner.update(message, 0, message.length);

        if (!rainbowSigner.verifySignature(sig))
        {
            fail("verification fails");
        }

         */
    }

    public static void main(String[] args)
    {
        runTest(new RainbowVTest());
    }
}
