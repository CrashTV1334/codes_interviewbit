package grp_18_assignment_2;

import java.math.BigInteger;

import java.util.*;

public class STSProtocolSimulation {
    public static void main(String[] args) throws Exception {

        Scanner sc  = new Scanner(System.in);
        System.out.println("************************************************************");
        System.out.println("Please enter a Prime Number g value as Public");
        BigInteger g = sc.nextBigInteger();
        System.out.println();
        System.out.println("Please enter another Prime Number p value as Public");
        BigInteger p = sc.nextBigInteger();
        System.out.println();
        System.out.println("************************************************************");
        //Creating the users as Alice and Bob
        User Alice = new User("Alice",g,p);
        User Bob = new User("Bob",g,p);
        System.out.println();
        //Genrating Public and Private key for each User
        System.out.println("************************************************************");
        Alice.generatePublicAndPrivateKey();
        Bob.generatePublicAndPrivateKey();
        System.out.println();

        System.out.println("************************************************************");
        BigInteger gx = Alice.AliceComputeExponentialAndRandomNumber();
        System.out.println();

        System.out.println("************************************************************");
        BigInteger gy = Bob.BobComputeExponentialAndRandomNumber();
        System.out.println();

        Alice.setBobExponential(gy);
        Bob.setAliceExponential(gx);
        
        Alice.setSecoundUserPublicKey(Bob.getPublicKey());
        Bob.setSecoundUserPublicKey(Alice.getPublicKey());

        System.out.println("************************************************************");
        Bob.BobSharedKeyCalculation();
        System.out.println();

        System.out.println("************************************************************");
        AnswerFromBobToAlice answerFromBobToAlice = Bob.BobCipherSignAndConcatenate();
        System.out.println();

        System.out.println("************************************************************");
        Alice.AliceSharedKeyCalculation();
        System.out.println();

        System.out.println("************************************************************");
        Alice.AliceDecryptionAndVerification(answerFromBobToAlice);
        System.out.println();

        System.out.println("************************************************************");
        AnswerFromAliceToBob answerFromAliceToBob = Alice.AliceCipherSignAndConcatenate();
        System.out.println();
        System.out.println("************************************************************");
        Bob.BobDecryptionAndVerification(answerFromAliceToBob);
        System.out.println();
        System.out.println("************************************************************");
        System.out.println("AUTHENTICATION FINISHED SUCCESSFULLY VIA SNS PROTOCOL");
        System.out.println();
        System.out.println("************************************************************");
        System.out.println("In out opinion it is not possible to perform a Man-In-The-Middle attack because "+
        "it is an asymmetric signature and verification, and each exchanged parameter is encrypted / decrypted using a symmetric key.");
        System.out.println("************************************************************");
    }
}
