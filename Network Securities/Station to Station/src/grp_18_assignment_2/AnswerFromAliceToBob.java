package grp_18_assignment_2;

public class AnswerFromAliceToBob {
    private byte [] cipheredSignature;

    public AnswerFromAliceToBob(byte[] cipheredSignature) {
        this.cipheredSignature = cipheredSignature;
    }

    public byte[] getCipheredSignature() {
        return cipheredSignature;
    }
}
