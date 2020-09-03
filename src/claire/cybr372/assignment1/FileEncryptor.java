package claire.cybr372.assignment1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
	
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("Random key=" + new String(Util.toHex(key)));
        System.out.println("initVector=" + new String(Util.toHex(initVector)));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path tempDir = Files.createTempDirectory("packt-crypto");
        
        final Path encryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files.pptx.encrypted");
        try (InputStream fin = FileEncryptor.class.getResourceAsStream("1 - Encrypting and Decrypting files.pptx");
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        
        LOG.info("Encryption finished, saved at " + encryptedPath);
        
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        final Path decryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files_decrypted.pptx");
        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        
        LOG.info("Decryption complete, open " + decryptedPath);
    }
    
    /**
     * Parses input parameters from main(). Ensures that they are textually valid, but performs no external validation
     * (ie, doesn't confirm that the given input file actually exists)
     * 
     * @param args The arguments as a char[]
     * @return An <code>InputParams</code> object
     */
    private static final InputParams fromStrs(char[][] args) 
    {
    	Util.inPlaceToLowerCase(args[0]);
    	CommandType type;
    	if(Arrays.equals("enc".toCharArray(), args[0]))
    		type = CommandType.ENC;
    	else if(Arrays.equals("dec".toCharArray(), args[0]))
    		type = CommandType.DEC;
    	else if(Arrays.equals("info".toCharArray(), args[0]))
    		type = CommandType.INFO;
    	else
    		throw new IllegalArgumentException("Was expecting `enc`, `dec`, or `info` as argument zero.");
    	
    	if(type == CommandType.INFO) {
    		return new InputParams(CommandType.INFO, new String(args[1]));
    	} else {
    		int start = 1;
    		String algo = ALGORITHM;
    		String cipher = CIPHER;
    		if(type == CommandType.ENC && args.length == 5) {
    			start = 2;
    		}
    		char[] pass = args[start];
    		String inFile = new String(args[start + 1]);
    		String outFile = new String(args[start + 2]);
    		return new InputParams(type, algo, cipher, pass, inFile, outFile);
    	}
    }
    
    private static enum CommandType {
    	ENC, DEC, INFO
    }
    
    /**
     * Input parameters for FileEncryptor
     * 
     * @author Claire
     */
    private static final class InputParams {
    	
    	private final CommandType type;
    	
    	private final String algorithm, cipher;
    	
    	private final char[] key;
    	
    	private final String inputFile, outputFile;
    	
    	public InputParams(CommandType encDec, String algorithm, String cipher, char[] key, String inputFile, String outputFile)
    	{
    		this.type = encDec;
    		this.algorithm = algorithm;
    		this.cipher = cipher;
    		this.key = key;
    		this.inputFile = inputFile;
    		this.outputFile = outputFile;
    	}
    	
    	public InputParams(CommandType info, String inputFile)
    	{
    		this.type = info;
    		this.inputFile = inputFile;
    		this.cipher = this.outputFile = this.algorithm = null;
    		this.key = null;
    	}

		/**
		 * @return the type
		 */
		public CommandType getType() {
			return type;
		}

		/**
		 * @return the algorithm
		 */
		public String getAlgorithm() {
			if(type == CommandType.INFO)
				throw new IllegalStateException("Attempted to call getAlgorithm on an INFO command");
			return algorithm;
		}

		/**
		 * @return the cipher
		 */
		public String getCipher() {
			if(type == CommandType.INFO)
				throw new IllegalStateException("Attempted to call getCipher on an INFO command");
			return cipher;
		}

		/**
		 * @return the key
		 */
		public char[] getKey() {
			if(type == CommandType.INFO)
				throw new IllegalStateException("Attempted to call getKey on an INFO command");
			return key;
		}

		/**
		 * @return the inputFile
		 */
		public String getInputFile() {
			return inputFile;
		}

		/**
		 * @return the outputFile
		 */
		public String getOutputFile() {
			if(type == CommandType.INFO)
				throw new IllegalStateException("Attempted to call getOutputFile on an INFO command");
			return outputFile;
		}
    	
    }
    
    /**
     * Utility for dealing with bytes and chars
     * 
     * If you run this through a plagiarism detector you may find a hit in a repository called HRTWiki. 
     * This is my repository and my code, I am re-using it for this assignment.
     * 
     * @author Claire
     */
    private static final class Util {
    	
    	private static final char[] HEX = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    	
    	/**
    	 * Converts a series of bytes into hexademical representation 
    	 * @param bytes The byte array to convert
    	 * @return An array of chars, each representing one nibble/hexadecimal character. Hex
    	 * will be in upper case [0-9A-F]
    	 */
    	public static final char[] toHex(byte[] bytes)
    	{
    		char[] chars = new char[bytes.length * 2];
    		for(int i = 0; i < bytes.length; i++) {
    			chars[i * 2 + 0] = HEX[(bytes[i] & 0xF0) >>> 4]; 
    			chars[i * 2 + 1] = HEX[(bytes[i] & 0x0F)]; 
    		}
    		return chars;
    	}
    	
    	/**
    	 * @param c A hexadecimal character of any case, in range [0-9A-Fa-f]
    	 * @return A nibble 
    	 */
    	private static final byte charToNibble(char c)
    	{
    		if(c >= '0' && c <= '9') 
    			return (byte) (c - '0');
    		else if(c >= 'A' && c <= 'F')
    			return (byte) (10 + (c - 'A'));
    		else if(c >= 'a' && c <= 'f')
    			return (byte) (10 + (c - 'a'));
    		else
    			throw new IllegalArgumentException("Hexadecimal characters are between 0-9, A-F, or a-f");
    	}
    	
    	/**
    	 * Converts a hexadecimal string into bytes
    	 * @param str The hexadecimal string as an array of characters, in any case
    	 * @return An array of bytes
    	 */
    	public static final byte[] fromHex(char[] str)
    	{
    		if((str.length & 1) == 1) 
    			throw new IllegalArgumentException("A hex string must have an even number of characters. Consier adding a leading zero.");
    		byte[] nBytes = new byte[str.length / 2];
    		for(int i = 0; i < nBytes.length; i++) {
    			byte b = charToNibble(str[i * 2]);
    			b <<= 4;
    			b += charToNibble(str[i * 2 + 1]);
    			nBytes[i] = b;
    		}
    		return nBytes;
    	}
    	
    	/**
    	 * Performs in place conversion from upper to lower case
    	 * 
    	 * @param in The array to convert
    	 */
    	public static final void inPlaceToLowerCase(char[] in)
    	{
    		for(int i = 0; i < in.length; i++)
    		{
    			char c = in[i];
    			if(c >= 'A' && c <= 'Z')
    				c = (char) (c + ('a' - 'A'));
    			in[i] = c;
    		}
    	}
    	
    }

}