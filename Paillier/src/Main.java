import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        final var paillier = new Paillier(2048);
        final var valueToEncrypt = new BigInteger("36319374621");

        final var encryptedValue = paillier.encrypt(valueToEncrypt);
        final var decryptedValue = paillier.decrypt(encryptedValue);

        var message = String.format("\tGiven value: %d\n\tEnctrypted value: %d\n\tDecrypted value: %d\n", valueToEncrypt, encryptedValue, decryptedValue);
        System.out.println(message);
    }

    static class Paillier {

        private BigInteger n;
        private BigInteger lambda;
        private BigInteger g;
        private BigInteger u;


        Paillier(Integer bits) {
            setupLambdaAndN(bits);
            setupG();
            this.u = g.modPow(lambda, n.pow(2))
                    .subtract(BigInteger.ONE)
                    .divide(n)
                    .modInverse(n);
        }

        public BigInteger encrypt(BigInteger valueToEncrypt) {
            final var n2 = n.pow(2);
            final var r = new BigInteger(n.bitLength(), new SecureRandom());
            return g.modPow(valueToEncrypt, n2)
                    .multiply(r.modPow(n, n2))
                    .mod(n2);
        }

        public BigInteger decrypt(BigInteger valueToDecrypt) {
            final var n2 = n.pow(2);
            return valueToDecrypt
                    .modPow(lambda, n2)
                    .subtract(BigInteger.ONE)
                    .divide(n)
                    .multiply(u)
                    .mod(n);
        }

        private void setupLambdaAndN(Integer bits) {
            var secureRandom = new SecureRandom();
            var p = BigInteger.probablePrime(bits / 2, secureRandom);
            var q = BigInteger.probablePrime(bits / 2, secureRandom);

            if (isPrimeGCDOne(p, q)) {
                this.n = p.multiply(q);
                this.lambda = calculateLambda(p, q);
                return;
            }

            setupLambdaAndN(bits);
        }

        private void setupG() {
            var secureRandom = new SecureRandom();
            var g = BigInteger.probablePrime(n.bitLength() / 2, secureRandom);
            if (isMultiplicativeGroupWithN(g)) {
                this.g = g;
                return;
            }

            setupG();
        }

        private boolean isPrimeGCDOne(BigInteger p, BigInteger q) {
            return p.multiply(q)
                    .gcd(p.subtract(BigInteger.ONE)
                            .multiply(q.subtract(BigInteger.ONE)))
                    .equals(BigInteger.ONE);
        }

        private BigInteger calculateLambda(BigInteger p, BigInteger q) {
            return p.subtract(BigInteger.ONE)
                    .multiply(q.subtract(BigInteger.ONE))
                    .divide(p.subtract(BigInteger.ONE)
                            .gcd(q.subtract(BigInteger.ONE)));
        }

        private boolean isMultiplicativeGroupWithN(BigInteger g) {
            final var n2 = n.pow(2);

            boolean isNotElementOfMultiplicativeGroup = g.compareTo(BigInteger.ZERO) <= 0 || g.compareTo(n2) >= 0 || !g.gcd(n2).equals(BigInteger.ONE);
            if (isNotElementOfMultiplicativeGroup) {
                return false;
            }

            var element = n.subtract(BigInteger.ONE)
                    .multiply(n.subtract(BigInteger.ONE));

            var gModPow = g.modPow(element, n2);
            return gModPow
                    .subtract(BigInteger.ONE)
                    .divide(n)
                    .gcd(n)
                    .equals(BigInteger.ONE);
        }

    }


}