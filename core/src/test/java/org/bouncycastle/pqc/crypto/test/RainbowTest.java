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

public class RainbowTest
    extends SimpleTest
{
    private int strength;
    private Version version;

    public RainbowTest(int strength, Version version)
    {
        this.strength = strength;
        this.version = version;
    }

    public String getName()
    {
        String name;
        switch (this.strength)
        {
            case 3:
                name = "Rainbow_III";
                break;
            case 5:
                name = "Rainbow_V";
                break;
            default:
                throw new IllegalArgumentException(
                        "No valid strength. Please choose one of the following: 3, 5");
        }

        switch (this.version)
        {
            case CLASSIC:
                name += "_Classic";
                break;
            case CIRCUMZENITHAL:
                name += "_Circumzenithal";
                break;
            case COMPRESSED:
                name += "_Compressed";
                break;
            default:
                throw new IllegalArgumentException(
                        "No valid version. Please choose one of the following: classic, circumzenithal, compressed");
        }

        return name;
    }

    public void performTest()
    {
        RainbowParameters params = new RainbowParameters(strength, version);
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
            fail("verification fails");
        }
    }

    public static void main(String[] args)
    {
        runTest(new RainbowTest(3, Version.CLASSIC));
        runTest(new RainbowTest(3, Version.CIRCUMZENITHAL));
        runTest(new RainbowTest(3, Version.COMPRESSED));
        runTest(new RainbowTest(5, Version.CLASSIC));
        runTest(new RainbowTest(5, Version.CIRCUMZENITHAL));
        runTest(new RainbowTest(5, Version.COMPRESSED));
    }
}
