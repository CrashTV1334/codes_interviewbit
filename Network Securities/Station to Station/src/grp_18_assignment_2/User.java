package grp_18_assignment_2;

import java.math.BigInteger;
import java.security.*;
import java.util.Random;

public class User {
    private String nameOfTheUser;
    private int xExponent;
    private int yExponent;
    private BigInteger g;
    private BigInteger p;
    //==Keys
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey secoundUserPublicKey;
    //==Exponentials
    private BigInteger BobExponential;
    private BigInteger AliceExponential;

    private BigInteger sharedKey;

    public User(String nameOfTheUser, BigInteger g, BigInteger p) {
        this.nameOfTheUser = nameOfTheUser;
        this.g = g;
        this.p = p;
        System.out.println("User created as below,");
        System.out.println("Name : "+nameOfTheUser);
    }
    public void generatePublicAndPrivateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        System.out.println("Public key and Private key genrated for " + nameOfTheUser);
    }

    //Step 1:Alice generates a random number x and computes and sends the exponential g^x to Bob.
    public BigInteger AliceComputeExponentialAndRandomNumber(){
        Random random = new Random();
        this.xExponent = random.nextInt(20);
        System.out.println("Step 1:Alice generates a random number x and computes and sends the exponential g^x mod p to Bob.");
        System.out.println("Random x generated : "+ this.xExponent);
        System.out.println("Exponential g^x mod p : "+this.g.pow(this.xExponent).mod(p));
        return this.AliceExponential = this.g.pow(this.xExponent).mod(p);
    }

    //Step 2:Bob generates a random number y and computes the exponential gy.
    public BigInteger BobComputeExponentialAndRandomNumber(){
        Random random = new Random();
        this.yExponent = random.nextInt(20);
        System.out.println("Step 2:Bob generates a random number y and computes the exponential g^y mod p.");
        System.out.println("Random y generated : "+ this.yExponent);
        System.out.println("Exponential g^y mod p : "+this.g.pow(this.yExponent).mod(p));
        return this.BobExponential = this.g.pow(this.yExponent).mod(p);
    }
    //Step 3: Bob computes the shared secret key K = (g^x)^y.
    public void BobSharedKeyCalculation(){
        System.out.println("Step 3: Bob computes the shared secret key K = (g^x)^y mod p");
        System.out.println("K = "+this.AliceExponential.pow(this.yExponent).mod(p));
        sharedKey = this.AliceExponential.pow(this.yExponent).mod(p);
    }

    //Step 4: Bob concatenates the exponentials (g^y, g^x) (order is important), signs them using his asymmetric (private)
    // key B, and then encrypts the signature with K. He sends the ciphertext along with his own exponential g^y to Alice.
    public AnswerFromBobToAlice BobCipherSignAndConcatenate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte [] AliceExponentialBytes = this.AliceExponential.toByteArray();
        byte [] BobExponentialBytes = this.BobExponential.toByteArray();
        byte [] concatenated = new byte [AliceExponentialBytes.length+BobExponentialBytes.length];
        int j=0;
        for(int i = 0; i < BobExponentialBytes.length; i++) {
            concatenated[i] = BobExponentialBytes[i];
        }
        for(int i = BobExponentialBytes.length;
            i < AliceExponentialBytes.length + BobExponentialBytes.length; i++) {
            concatenated[i] = AliceExponentialBytes[j];
            j++;
        }
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(this.privateKey);
        sign.update(concatenated);
        byte[] signBytes = sign.sign();
        AESEncryptDecryptMessage aesEncryptDecryptMessage = new AESEncryptDecryptMessage();
        aesEncryptDecryptMessage.setKey(sharedKey.toString());
        byte [] cipheredSignature = aesEncryptDecryptMessage.encrypt(signBytes);
        System.out.println();
        System.out.println("Step 4: Bob concatenates the exponentials (g^y mod p, g^x mod p) (order is important),"+
        " signs them using his asymmetric (private)key B, and then encrypts the signature with K. He sends the ciphertext along with his own exponential g^y to Alice.");
        return new AnswerFromBobToAlice(this.getBobExponential(),cipheredSignature);
    }
    //Step 5: Alice computes the shared secret key K = (g^y)^x.
    public void AliceSharedKeyCalculation(){
        System.out.println("Step 5: Alice computes the shared secret key K = (g^y)^x mod p");
        System.out.println("K = " + this.BobExponential.pow(this.xExponent).mod(p));
        sharedKey = this.BobExponential.pow(this.xExponent).mod(p);
    }
    //Step 6 : Alice decrypts and verifies Bob's signature using his asymmetric public key.
        public void AliceDecryptionAndVerification(AnswerFromBobToAlice bobAnswer) throws Exception {
        System.out.println("Step 6 : Alice decrypts and verifies Bob's signature using his asymmetric public key");
        AESEncryptDecryptMessage aes = new AESEncryptDecryptMessage();
        aes.setKey(sharedKey.toString());
        byte [] decryptedSignature = aes.decrypt(bobAnswer.getCipheredSignature());
        byte [] BobExponentialBytes = this.BobExponential.toByteArray();
        byte [] AliceExponentialBytes = this.AliceExponential.toByteArray();
        byte [] concatenated = new byte [AliceExponentialBytes.length+BobExponentialBytes.length];
            int j=0;
            for(int i = 0; i < BobExponentialBytes.length; i++) {
                concatenated[i] = BobExponentialBytes[i];
            }
            for(int i = BobExponentialBytes.length;
                i < AliceExponentialBytes.length + BobExponentialBytes.length; i++) {
                concatenated[i] = AliceExponentialBytes[j];
                j++;
            }
            Signature verifySignature = Signature.getInstance("SHA256withRSA");
            verifySignature.initVerify(this.secoundUserPublicKey);
            verifySignature.update(concatenated);
            boolean isVerified = verifySignature.verify(decryptedSignature);
            if(!isVerified) { 
                System.out.println("Unable to verify Bob's Signature");
                throw new Exception("Verification failed."); 
            }
            else{System.out.println("Bob's signature Verified");}
    }

    //Step 7: Alice concatenates the exponentials (gx, gy) (order is important), signs them using her asymmetric
    // (private) key A, and then encrypts the signature with K. She sends the ciphertext to Bob.
    public AnswerFromAliceToBob AliceCipherSignAndConcatenate()
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println("Step 7: Alice concatenates the exponentials (g^x mod p, g^y mod p) (order is important), signs them using her asymmetric "+
        "(private) key A, and then encrypts the signature with K. She sends the ciphertext to Bob.");
        byte [] AliceExponentialBytes = this.AliceExponential.toByteArray();
        byte [] BobExponentialBytes = this.BobExponential.toByteArray();
        byte [] concatenated = new byte [AliceExponentialBytes.length+BobExponentialBytes.length];
        int j=0;
        for(int i = 0; i < AliceExponentialBytes.length; i++) {
            concatenated[i] = AliceExponentialBytes[i];
        }
        for(int i = AliceExponentialBytes.length;
            i < AliceExponentialBytes.length + BobExponentialBytes.length; i++) {
            concatenated[i] = BobExponentialBytes[j];
            j++;
        }
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(this.privateKey);
        sign.update(concatenated);
        byte[] signBytes = sign.sign();
        AESEncryptDecryptMessage aesEncryptDecryptMessage = new AESEncryptDecryptMessage();
        aesEncryptDecryptMessage.setKey(sharedKey.toString());
        byte [] cipheredSignature = aesEncryptDecryptMessage.encrypt(signBytes);
        return new AnswerFromAliceToBob(cipheredSignature);
    }
    //Step 8:Bob decrypts and verifies Alice's signature using her asymmetric public key.
    public void BobDecryptionAndVerification(AnswerFromAliceToBob aliceAnswer) throws Exception {
        System.out.println("Step 8:Bob decrypts and verifies Alice's signature using her asymmetric public key.");
        AESEncryptDecryptMessage aes = new AESEncryptDecryptMessage();
        aes.setKey(sharedKey.toString());
        byte [] decryptedSignature = aes.decrypt(aliceAnswer.getCipheredSignature());
        byte [] BobExponentialBytes = this.BobExponential.toByteArray();
        byte [] AliceExponentialBytes = this.AliceExponential.toByteArray();
        byte [] concatenated = new byte [AliceExponentialBytes.length+BobExponentialBytes.length];
        int j=0;
        for(int i = 0; i < AliceExponentialBytes.length; i++) {
            concatenated[i] = AliceExponentialBytes[i];
        }
        for(int i = AliceExponentialBytes.length;
            i < AliceExponentialBytes.length + BobExponentialBytes.length; i++) {
            concatenated[i] = BobExponentialBytes[j];
            j++;
        }
        Signature verifySignature = Signature.getInstance("SHA256withRSA");
        verifySignature.initVerify(this.secoundUserPublicKey);
        verifySignature.update(concatenated);
        boolean isVerified = verifySignature.verify(decryptedSignature);
        if(!isVerified) {
            System.out.println("Unable to verify Alice's Signature");
            throw new Exception("Verification failed."); }
        else{System.out.println("Alice's signature Verified");}
    }


    public String getNameOfTheUser() {
        return nameOfTheUser;
    }

    public void setNameOfTheUser(String nameOfTheUser) {
        this.nameOfTheUser = nameOfTheUser;
    }

    public int getxExponent() {
        return xExponent;
    }

    public void setxExponent(int xExponent) {
        this.xExponent = xExponent;
    }

    public int getyExponent() {
        return yExponent;
    }

    public void setyExponent(int yExponent) {
        this.yExponent = yExponent;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PublicKey getSecoundUserPublicKey() {
        return secoundUserPublicKey;
    }

    public void setSecoundUserPublicKey(PublicKey secoundUserPublicKey) {
        this.secoundUserPublicKey = secoundUserPublicKey;
    }

    public BigInteger getBobExponential() {
        return BobExponential;
    }

    public void setBobExponential(BigInteger bobExponential) {
        BobExponential = bobExponential;
    }

    public BigInteger getAliceExponential() {
        return AliceExponential;
    }

    public void setAliceExponential(BigInteger aliceExponential) {
        AliceExponential = aliceExponential;
    }
}
