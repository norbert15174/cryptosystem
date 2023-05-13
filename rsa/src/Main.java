import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        var rsa = new RSA(768);
        var text = "testytuiosnncdherkdcsdssfdsfds bsi tets12";

        var encrypted = rsa.encrypt(encodeMessage(text));
        var decrypted = rsa.decrypt(encrypted);
        System.out.println("Value: " + text);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decodeMessage(decrypted));
    }

    static class RSA {
        private BigInteger privateKey;
        private BigInteger publicKey;
        private BigInteger n;
        private BigInteger phi;

        public RSA(int bits) {
            generatePhiAndN(bits);
            generateKeys();
        }

        private void generatePhiAndN(int bits) {
            var secureRandom = new SecureRandom();
            var p = BigInteger.probablePrime(bits / 2, secureRandom);
            var q = BigInteger.probablePrime(bits / 2, secureRandom);

            if (isPrimeGCDOne(p, q)) {
                this.n = p.multiply(q);
                this.phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                return;
            }

            generatePhiAndN(bits);
        }

        private void generateKeys() {
            var secureRandom = new SecureRandom();
            var e = BigInteger.probablePrime(n.bitLength() / 2, secureRandom);
            if (phi.gcd(e).equals(BigInteger.ONE)) {
                this.publicKey = e;
                this.privateKey = e.modInverse(phi);
                return;
            }
            generateKeys();
        }

        private boolean isPrimeGCDOne(BigInteger p, BigInteger q) {
            return p.multiply(q)
                    .gcd(p.subtract(BigInteger.ONE)
                            .multiply(q.subtract(BigInteger.ONE)))
                    .equals(BigInteger.ONE);
        }

        private BigInteger encrypt(BigInteger value) {
            return value.modPow(privateKey, n);
        }

        private BigInteger decrypt(BigInteger value) {
            return value.modPow(publicKey, n);
        }

    }

    private static BigInteger encodeMessage(String message) {
        return new BigInteger(message.getBytes());
    }

    private static String decodeMessage(BigInteger encodedMessage) {
        return new String(encodedMessage.toByteArray(), StandardCharsets.UTF_8);
    }

}