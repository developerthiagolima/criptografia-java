
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public final class CriptografiaUtil {
    public static final String ALGORITMO_PADRAO = "RSA";
    public static final String ALGORITMO_PADRAO_UMAVIA = "SHA1";
    private static final String CHAVE_ASSEMBLA = "se.assembla.jce.provider.ms.MSRSAPrivateKey";
    private static final String PROVEDOR = "assembla";

    private CriptografiaUtil() {
    }

    public static byte[] criptografar(Certificate certificate, byte[] conteudo) throws Exception {
        try {
            return CriptografiaUtil.criptografar(ALGORITMO_PADRAO, certificate, conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw new Exception(e.getMessage(), e);
        }
    }

    public static byte[] criptografar(Key chave, byte[] conteudo) throws Exception {
        try {
            return CriptografiaUtil.criptografar(ALGORITMO_PADRAO, chave, conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw new Exception(e.getMessage(), e);
        }
    }

    public static byte[] criptografar(String algoritmo, Certificate certificate, byte[] conteudo) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        return CriptografiaUtil.criptografar(algoritmo, certificate.getPublicKey(), conteudo);
    }

    public static byte[] criptografar(String algoritmo, Key chave, byte[] conteudo) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            Cipher cipher = CriptografiaUtil.obterCipher(algoritmo, chave);
            cipher.init(1, chave);
            return cipher.doFinal(conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw e;
        }
    }

    public static byte[] criptografar(byte[] conteudo) throws NoSuchAlgorithmException {
        return CriptografiaUtil.criptografar(ALGORITMO_PADRAO_UMAVIA, conteudo);
    }

    public static byte[] criptografar(String algoritmo, byte[] conteudo) throws NoSuchAlgorithmException {
        try {
            MessageDigest digest = MessageDigest.getInstance(algoritmo);
            return digest.digest(conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw e;
        }
    }

    public static byte[] decriptografar(Certificate certificate, byte[] conteudo) throws Exception {
        try {
            return CriptografiaUtil.decriptografar(ALGORITMO_PADRAO, certificate, conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw new Exception(e.getMessage(), e);
        }
    }

    public static byte[] decriptografar(Key chave, byte[] conteudo) throws Exception {
        try {
            return CriptografiaUtil.decriptografar(ALGORITMO_PADRAO, chave, conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw new Exception(e.getMessage(), e);
        }
    }

    public static byte[] decriptografar(String algoritmo, Certificate certificate, byte[] conteudo) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        return CriptografiaUtil.decriptografar(algoritmo, certificate.getPublicKey(), conteudo);
    }

    public static byte[] decriptografar(String algoritmo, Key chave, byte[] conteudo) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {
            Cipher cipher = CriptografiaUtil.obterCipher(algoritmo, chave);
            cipher.init(2, chave);
            return cipher.doFinal(conteudo);
        }
        catch (NoSuchAlgorithmException e) {
            throw e;
        }
    }

    private static Cipher obterCipher(String algoritmo, Key chave) throws NoSuchAlgorithmException, NoSuchPaddingException {
        if (chave.getClass().getName().toUpperCase().equals(CHAVE_ASSEMBLA.toUpperCase())) {
            try {
                return Cipher.getInstance(algoritmo, PROVEDOR);
            }
            catch (NoSuchProviderException e) {
                return Cipher.getInstance(algoritmo);
            }
        }
        return Cipher.getInstance(algoritmo);
    }
}

