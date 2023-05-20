import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class Main {
    public static void main(String[] args) {
        var signatureAlgorithm = new SchnorrAlgorithm(12);
        var signingKey = signatureAlgorithm.generateSigningKey();
        var publicKey = signatureAlgorithm.generatePublicKey();
        var message = new BigInteger("2132145423432");

        var nonBlind = signatureAlgorithm.signAsNonBlind(message, signingKey);
        var blind = signatureAlgorithm.signAsBlind(message, signingKey, publicKey);

        System.out.println("nonBlind result: " + signatureAlgorithm.verify(message, nonBlind, publicKey));
        System.out.println("blind result: " + signatureAlgorithm.verify(message, blind, publicKey));
    }

    static class SchnorrAlgorithm {
        private final BigInteger primeNumber;
        private final BigInteger generatedElement;
        private final GroupGenerator groupGenerator;

        public SchnorrAlgorithm(int numBits) {
            this.primeNumber = BigInteger.probablePrime(numBits, new SecureRandom());
            this.groupGenerator = new GroupGenerator(numBits, primeNumber, primeNumber);
            this.generatedElement = groupGenerator.generateElement();
        }

        public Signature signAsNonBlind(BigInteger message, Key signingKey) {
            var r = signingKey.groupGenerator.generateElement();
            var elipticCurvePoint = r.multiply(groupGenerator.getG());
            var c = signingKey.groupGenerator.hash(elipticCurvePoint, message);
            return new Signature(elipticCurvePoint, c.multiply(signingKey.value()).add(r).mod(primeNumber));
        }

        public Signature signAsBlind(BigInteger message, Key signingKey, Key publicKey) {
            var r = signingKey.groupGenerator.generateElement();
            var alfa = publicKey.groupGenerator.generateElement();
            var beta = publicKey.groupGenerator.generateElement();
            var elipticCurvePoint = r.multiply(groupGenerator.getG());
            var elipticCurvePointPrime = elipticCurvePoint.add(alfa.multiply(publicKey.groupGenerator.getG())).add(beta.multiply(publicKey.value()));
            var cPrim = publicKey.groupGenerator.hash(elipticCurvePointPrime, message);
            var c = (cPrim.add(beta)).mod(primeNumber);
            var s = c.multiply(signingKey.value()).add(r).mod(primeNumber);
            var canSign = (s.multiply(groupGenerator.getG())).equals(c.multiply(publicKey.value()).add(elipticCurvePoint));
            if (canSign) {
                return new Signature(elipticCurvePointPrime, (s.add(alfa)).mod(primeNumber));
            }
            throw new SecurityException("Cannot sign the message");
        }

        public boolean verify(BigInteger message, Signature signature, Key publicKey) {
            var cPrim = publicKey.groupGenerator.hash(signature.elipticCurvePoint(), message);
            var left = signature.value().multiply(publicKey.groupGenerator.getG());
            var right = signature.elipticCurvePoint().add(cPrim.multiply(publicKey.value()));
            return Objects.equals(left, right);
        }

        public Key generateSigningKey() {
            return new Key(generatedElement, groupGenerator);
        }

        public Key generatePublicKey() {
            return new Key(generatedElement.multiply(groupGenerator.getG()), groupGenerator);
        }

        static class GroupGenerator {
            private final BigInteger groupModulo;
            private final BigInteger groupOrder;
            private final BigInteger g;
            private final BigInteger r;
            private final BigInteger h;
            private final SecureRandom random = new SecureRandom();

            public GroupGenerator(int numBits, BigInteger groupModulo, BigInteger groupOrder) {
                this.groupModulo = groupModulo;
                this.groupOrder = groupOrder;
                this.r = (groupModulo.subtract(BigInteger.ONE)).divide(groupOrder);
                this.h = generateH(groupModulo, numBits);
                this.g = generateG(groupModulo);
            }

            public BigInteger hash(BigInteger R, BigInteger message) {
                var rBytes = R.toByteArray();
                var messageBytes = message.toByteArray();
                var buffer = ByteBuffer.allocate(rBytes.length + messageBytes.length);
                buffer.put(rBytes);
                buffer.put(messageBytes);
                try {
                    var md = MessageDigest.getInstance("SHA-256");
                    md.update(buffer.array());
                    return new BigInteger(md.digest()).mod(groupModulo);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            public BigInteger generateElement() {
                var element = new BigInteger(groupModulo.bitLength(), random);
                return isElementNotValid(element) ? generateElement() : element;
            }

            private boolean isElementNotValid(BigInteger x) {
                return x.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(groupModulo) >= 0 || !x.modPow(groupOrder, groupModulo).equals(BigInteger.ONE);
            }

            private BigInteger generateG(BigInteger groupModulo) {
                return h.modPow(r, groupModulo);
            }

            private BigInteger generateH(BigInteger groupModulo, int numBits) {
                var h = new BigInteger(numBits, random);
                return isHValidNumber(groupModulo, h) ? h : generateH(groupModulo, numBits);
            }

            private boolean isHValidNumber(BigInteger groupModulo, BigInteger h) {
                return h.compareTo(BigInteger.ONE) <= 0 || h.compareTo(groupModulo) >= 0 || h.modPow(r, groupModulo).equals(BigInteger.ONE);
            }

            public BigInteger getG() {
                return g;
            }

        }

        record Signature(BigInteger elipticCurvePoint, BigInteger value) {
        }

        record Key(BigInteger value, GroupGenerator groupGenerator) {
        }

    }

}