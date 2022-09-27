package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RainbowVTest
    extends SimpleTest
{
    static int success = 0;
    static int fail = 0;

    public String getName()
    {
        return "Rainbow_V";
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters(5);

        SecureRandom random;
        try
        {
            random = SecureRandom.getInstance("SHA1PRNG");
        }
        catch (NoSuchAlgorithmException e)
        {
            random = new SecureRandom();
        }

        RainbowKeyPairGenerator rainbowKeyGen = new RainbowKeyPairGenerator();
        RainbowKeyGenerationParameters genParam = new RainbowKeyGenerationParameters(random, params);

        rainbowKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = rainbowKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        DigestingMessageSigner rainbowSigner = new DigestingMessageSigner(new RainbowSigner(), params.getHash_algo());

        rainbowSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        rainbowSigner.update(message, 0, message.length);
        byte[] sig = rainbowSigner.generateSignature();

        rainbowSigner.init(false, pair.getPublic());
        rainbowSigner.update(message, 0, message.length);

        if (!rainbowSigner.verifySignature(sig))
        {
            RainbowVTest.fail++;
            fail("verification fails");
        }
        RainbowVTest.success++;
    }

    public static void main(String[] args)
    {
        for (int i = 0; i < 100; i++)
        {
            runTest(new RainbowVTest());
        }
        System.out.println("success: "+RainbowVTest.success+" failure: "+RainbowVTest.fail);
        //runTest(new RainbowVTest());
    }
}
