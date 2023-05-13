import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Main {
    public static void main(String[] args) {
        var value = "testowy kod";
        var vernam = new Vernam(value);
        var valueAfterCode = StringConverter.xorOperation(StringConverter.convertStringToBits(value), vernam.getCode());

        System.out.println("Text to code: " + value);
        System.out.println("After encode: " + valueAfterCode);
        System.out.println("code: " + vernam.getCode());
        System.out.println("After decode: " + StringConverter.convertBitsToString(StringConverter.xorOperation(valueAfterCode, vernam.getCode())));

    }

    static class Vernam {
        private final String code;

        public String getCode() {
            return code;
        }

        public Vernam(String value) {
            var bitsValue = StringConverter.convertStringToBits(value);
            this.code = generateCode(bitsValue.length());
        }

        private String generateCode(int length) {
            var secureRandom = new SecureRandom();
            var p = BigInteger.probablePrime(length / 2, secureRandom);
            var q = BigInteger.probablePrime(length / 2, secureRandom);
            var n = p.multiply(q);
            var startValue = new BigInteger(n.bitLength(), new Random());
            return blumBlumShub(length, "", startValue, n);
        }

        private String blumBlumShub(int length, String code, BigInteger s, BigInteger n) {
            if (code.length() == length) {
                return code;
            }

            BigInteger x = s.pow(2).mod(n);
            code += x.mod(new BigInteger("2")).toString();
            return blumBlumShub(length, code, x, n);
        }

    }

    static class StringConverter {
        public static String convertStringToBits(String value) {
            return new BigInteger(value.getBytes()).toString(2);
        }

        public static String convertBitsToString(String value) {
            return new String(new BigInteger(value, 2).toByteArray());
        }

        public static String xorOperation(String val1, String val2) {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < val1.length(); i++) {
                result.append((Character.getNumericValue(val1.charAt(i)) + Character.getNumericValue(val2.charAt(i))) % 2);
            }
            return result.toString();
        }

    }

}