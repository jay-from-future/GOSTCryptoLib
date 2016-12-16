package com.crypto;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * Реализация цифровой подписи, основонной на эллиптической кривой по ГОСТ 34.10-2012.
 *
 * @author Grigorii Liullin.
 */
public class GOST3410DigitalSignature {

    private static final Logger LOG = Logger.getLogger(GOST3410DigitalSignature.class.getName());

    private final String CURVE_P_256 = "P-256";

    private ECParameterSpec ecSpec;
    private ECCurve curve;

    public GOST3410DigitalSignature() {
        Security.addProvider(new BouncyCastleProvider());
        ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_P_256);
        curve = ecSpec.getCurve();
    }

    /**
     * Генерирует подпись для указанного файла
     *
     * @param file Входной файл, для которого будет генерироваться подпись.
     * @return Сгенерированная подпись.
     * @throws IOException Не удается открыть для чтения входной файл.
     */
    public String generateSignatureForFile(File file, BigInteger d) throws IOException {
        LOG.debug("+generateSignatureForFile");
        String fileAbsolutePath = file.getAbsolutePath();
        LOG.debug("Input file : " + fileAbsolutePath);
        byte[] msg = new byte[(int) file.length()];
        FileInputStream fileInputStream = new FileInputStream(file);
        int readResult = fileInputStream.read(msg);
        if (readResult < 0) {
            String errorMsg = "Cannot read from input file : " + fileAbsolutePath;
            LOG.error(errorMsg);
            throw new IOException(errorMsg);
        }
        String signature = generateSignature(msg, d);
        LOG.debug("Signature : " + signature);
        LOG.debug("-generateSignatureForFile");
        return signature;
    }

    public boolean verifySignatureForFile(File file, String signature, ECPoint Q) throws IOException {
        LOG.debug("+verifySignatureForFile");
        String fileAbsolutePath = file.getAbsolutePath();
        LOG.debug("Input file : " + fileAbsolutePath);
        byte[] msg = new byte[(int) file.length()];
        FileInputStream fileInputStream = new FileInputStream(file);
        int readResult = fileInputStream.read(msg);
        if (readResult < 0) {
            String errorMsg = "Cannot read from input file : " + fileAbsolutePath;
            LOG.error(errorMsg);
            throw new IOException(errorMsg);
        }
        boolean verification = verifySignature(msg, signature, Q);
        LOG.debug("Signature : " + signature);
        LOG.debug("Signature is valid : " + verification);
        LOG.debug("-verifySignatureForFile");
        return verification;
    }

    /**
     * Генерация подписи:
     * <p>
     * 1 Вычислить хеш сообщения M: H=hash(M). На этом шаге используется хеш-функция Стрибог, о которой я уже писал на хабре;
     * 2 Вычислить целое число α, двоичным представление которого является H;
     * 3 Определить e=α mod n, если e=0, задать e=1;
     * 4 Сгенерировать случайное число k, удовлетворяющее условию 0<k<n;
     * 5 Вычислить точку эллиптической кривой C=k*G;
     * 6 Определить r = xC mod n, где xC — x-координата точки C. Если r=0, то вернуться к шагу 4;
     * 7 Вычислить значение s = (rd+ke) mod n. Если s=0, то вернуться к шагу 4;
     * 8 Вернуть значение r||s в качестве цифровой подписи.
     *
     * @param msg Сообщение, которое необходимо подписать
     * @return Сгенерированная подпись
     */
    public String generateSignature(byte[] msg, BigInteger d) {

        LOG.debug("+generateSignature");

        // 1 Вычислить хеш сообщения M: H=hash(M).
        byte[] hash = GOST3411HashStribog.stribog256BigDigest(msg);
        LOG.debug("hash : " + convertByteArrayToHexString(hash));

        //  2 Вычислить целое число α, двоичным представление которого является H;
        BigInteger alpha = new BigInteger(hash); // тут никаких проблем - сконвертировали массив байт в целое число
        LOG.debug("alpha : " + alpha);

        // 3 Определить e=α mod n, если e=0, задать e=1;
        BigInteger n = curve.getOrder(); // n - порядок точки G
        BigInteger e = alpha.mod(n);
        if (e.compareTo(BigInteger.ZERO) == 0) {
            e = BigInteger.ONE;
        }
        LOG.debug("e : " + e);

        BigInteger k;
        BigInteger r;
        BigInteger s;
        ECPoint G;
        ECPoint C;
        do {
            // 4 Сгенерировать случайное число k, удовлетворяющее условию 0<k<n;
            do {
                k = new BigInteger(n.bitLength(), new SecureRandom());
            } while ((k.compareTo(BigInteger.ZERO) < 0) || (k.compareTo(n) > 0));
            // 5 Вычислить точку эллиптической кривой C=k*G;
            G = ecSpec.getG();
            C = (G.multiply(k)).normalize();
            // 6 Определить r = xC mod n, где xC — x-координата точки C. Если r=0, то вернуться к шагу 4;
            r = (C.getAffineXCoord().toBigInteger()).mod(n);
            // 7 Вычислить значение s = (rd+ke) mod n. Если s=0, то вернуться к шагу 4;
            s = ((r.multiply(d)).add(k.multiply(e))).mod(n);
        } while (r.compareTo(BigInteger.ZERO) == 0 || s.compareTo(BigInteger.ZERO) == 0);

        LOG.debug("k : " + k);
        LOG.debug("G : " + G);
        LOG.debug("C : " + C);
        LOG.debug("r : " + r);
        LOG.debug("s : " + s);
        LOG.debug("n : " + n);

        // удаляет 0x00 из начала, свзано с представлением числа в BigInteger
        byte[] rByteArray = removeLeadingZeros(r.toByteArray());
        byte[] sByteArray = removeLeadingZeros(s.toByteArray());
        int length = rByteArray.length + sByteArray.length;
        byte[] result = new byte[length];

        System.arraycopy(rByteArray, 0, result, 0, rByteArray.length);
        System.arraycopy(sByteArray, 0, result, rByteArray.length, sByteArray.length);

        LOG.debug("rByteArray : " + convertByteArrayToHexString(rByteArray));
        LOG.debug("sByteArray : " + convertByteArrayToHexString(sByteArray));
        LOG.debug("result : " + convertByteArrayToHexString(result));

        LOG.debug("-generateSignature");
        return convertByteArrayToHexString(result);
    }

    /**
     * Проверка подписи:
     * <p>
     * 1 По полученной подписи восстановить числа r и s.
     * Если не выполнены неравенства 0<r<n и 0<s<n, тогда вернуть «подпись не верна»;
     * 2 Вычислить хеш сообщения M: H=h(M);
     * 3 Вычислить целое число α, двоичным представление которого является H;
     * 4 Определить e=α mod n, если e=0, задать e=1;
     * 5 Вычислить v = e-1 mod n;
     * 6 Вычислить значения z1 = s*v mod n и z2 = -r*v mod n;
     * 7 Вычислить точку эллиптической кривой C = z1*G + z2*Q;
     * 8 Определить R = xc mod n, где xc — x-координата точки C;
     * 9 Если R=r, то подпись верна. В противном случае подпись не принимается.
     *
     * @param msg          Сообщение
     * @param signatureStr Подпись
     * @return Результат проверки подписи: true - если подпись верна, иначе - false.
     */
    public boolean verifySignature(byte[] msg, String signatureStr, ECPoint Q) {
        LOG.debug("+verifySignature");

        byte[] signature = convertHexStringToByteArray(signatureStr);

        // 1 По полученной подписи восстановить числа r и s.
        byte[] rByteArray = new byte[signature.length / 2];
        byte[] sByteArray = new byte[signature.length / 2];

        System.arraycopy(signature, 0, rByteArray, 0, rByteArray.length);
        System.arraycopy(signature, signature.length / 2, sByteArray, 0, sByteArray.length);

        // добавляет 0x00 в начало, если необходимо. свзано с представлением числа в BigInteger
        if (new BigInteger(rByteArray).signum() == -1) {
            rByteArray = addLeadingZeros(rByteArray);
        }
        if (new BigInteger(sByteArray).signum() == -1) {
            sByteArray = addLeadingZeros(sByteArray);
        }

        BigInteger r = new BigInteger(rByteArray);
        BigInteger s = new BigInteger(sByteArray);

        LOG.debug("signByteArray : " + convertByteArrayToHexString(signature));
        LOG.debug("rByteArray : " + convertByteArrayToHexString(rByteArray));
        LOG.debug("sByteArray : " + convertByteArrayToHexString(sByteArray));
        LOG.debug("r : " + new BigInteger(rByteArray));
        LOG.debug("s : " + new BigInteger(sByteArray));

        boolean result = false;
        BigInteger n = curve.getOrder(); // n - порядок точки G
        // Если не выполнены неравенства 0<r<n и 0<s<n, тогда вернуть «подпись не верна»;
        if (r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(n) < 0
                && s.compareTo(BigInteger.ZERO) > 0 && s.compareTo(n) < 0) {

            // 2 Вычислить хеш сообщения M: H=hash(M).
            byte[] hash = GOST3411HashStribog.stribog256BigDigest(msg);

            LOG.debug("hash : " + convertByteArrayToHexString(hash));

            // 3 Вычислить целое число α, двоичным представление которого является H;
            BigInteger alpha = new BigInteger(hash); // тут никаких проблем - сконвертировали массив байт в целое число
            LOG.debug("alpha : " + alpha);

            // 4 Определить e=α mod n, если e=0, задать e=1;
            BigInteger e = alpha.mod(n);
            LOG.debug("e : " + e);

            // 5 Вычислить v = e-1 mod n;
            BigInteger v = e.modInverse(n);
            LOG.debug("v : " + v);

            // 6 Вычислить значения z1 = s*v mod n и z2 = -r*v mod n;
            BigInteger z1 = (s.multiply(v)).mod(n);
            BigInteger z2 = (r.negate().multiply(v)).mod(n);

            LOG.debug("z1 : " + z1);
            LOG.debug("z2 : " + z2);

            // 7 Вычислить точку эллиптической кривой C = z1*G + z2*Q;
            ECPoint G = ecSpec.getG();
            ECPoint C = ((G.multiply(z1)).add(Q.multiply(z2))).normalize();

            LOG.debug("G : " + G);
            LOG.debug("C : " + C);

            // 8 Определить R = xc mod n, где xc — x-координата точки C;
            BigInteger R = C.getAffineXCoord().toBigInteger().mod(n);

            // 9 Если R=r, то подпись верна.
            result = r.compareTo(R) == 0;

            LOG.debug("R : " + R);
            LOG.debug("r : " + r);
            LOG.debug("(R == r) ? : " + result);
        } else {
            if (r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(n) < 0) {
                LOG.debug("r is not in range (0, n)");
            }
            if (s.compareTo(BigInteger.ZERO) > 0 && s.compareTo(n) < 0) {
                LOG.debug("s is not in range (0, n)");
            }
        }
        LOG.debug("Signature is valid : " + result);
        LOG.debug("-verifySignature");
        return result;
    }

    public static byte[] convertHexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return result;
    }

    public String convertByteArrayToHexString(byte[] digest) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : digest) {
            int iv = (int) b & 0xFF;
            if (iv < 0x10) {
                stringBuilder.append('0');
            }
            stringBuilder.append(Integer.toHexString(iv).toUpperCase());
        }
        return stringBuilder.toString();
    }

    public BigInteger generatePrivateKey() {
        BigInteger q = curve.getOrder();
        BigInteger d;
        do {
            d = new BigInteger(q.bitLength(), new SecureRandom());
        } while (d.signum() != 1 || (d.compareTo(q) > 0)); // необходимо получить 0 < d < q
        return d;
    }

    public ECPoint generatePublicKey(BigInteger d) {
        return ((ecSpec.getG()).multiply(d)).normalize();
    }

    public byte[] removeLeadingZeros(byte[] array) {
        byte[] arrayCopy = Arrays.copyOf(array, array.length);
        if (arrayCopy[0] == 0) {
            byte[] tmp = new byte[arrayCopy.length - 1];
            System.arraycopy(arrayCopy, 1, tmp, 0, tmp.length);
            arrayCopy = tmp;
        }
        return arrayCopy;
    }

    public byte[] addLeadingZeros(byte[] array) {
        byte[] arrayCopy = new byte[array.length + 1];
        arrayCopy[0] = 0x00;
        System.arraycopy(array, 0, arrayCopy, 1, array.length);
        return arrayCopy;
    }

    public ECPoint createECPoint(BigInteger x, BigInteger y) {
        return curve.createPoint(x, y);
    }

    public ECCurve getCurve() {
        return curve;
    }
}
