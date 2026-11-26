import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Crypto {
    public byte[] legacy(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    public byte[] digest(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }
}
