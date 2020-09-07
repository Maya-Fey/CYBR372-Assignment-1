package claire.cybr372.assignment1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
	
    private static final String DEFAULT_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) {
        //Convert the arguments to char arrays, wipe the originals, and then enter into a new function (hopefully the args[] will GC, giving just an extra layer of protection)
    	char[][] charargs = Util.toCharArrayArray(args);
    	for(String s : args)
    		CryptUtil.wipeString(s);
    	args = null;
    	mainInner(charargs);
    }
    
    private static final void mainInner(char[][] args)
    {
    	InputParams params = fromStrs(args);
    	switch(params.getType()) {
    		case INFO:
    			info(params);
    			break;
    		case ENC:
    			enc(params);
    			break;
    		case DEC:
    			dec(params);
    			break;
    	}
    }
    
    /*
	 * IMPORTANT NOTE REGARDING FILE FORMAT:
	 * 
	 * 0x09 (1 byte)
	 * Block size (1 byte)
	 * Key size (1 byte)
	 * <length of algorithm string> (1 byte)
	 * algorithm string (length bytes long)
	 * <length of cipher string>
	 * cipher (length bytes long)
	 * salt for cipher key (16 bytes)
	 * salt for MAC key (16 bytes)
	 * IV (blocksize bytes long)
	 * MAC of plaintext (32 bytes)
	 * 
	 * The rationale for this file format is as follows:
	 * 
	 *   - The 0x09 guard is just to make it so that more files are rejected early rather than causing IO errors or decrypt errors. Not foolproof, obviously, a random file has a 1/256 chance of having 0x9 on its own.
	 *   - Block and key size are only one byte as they themselves are in bytes. A block size of 255 bytes would be over two thousand bits, which is not something we're likely to see.
	 *   - Separate salts for cipher key and mac key as it's a convenient way to produce two different keys from the same master secret
	 *   - MAC at the beginning so we can read it without dropping out of the cyrpto stream
	 *   - MAC is of plaintext because mac-then-encrypt is about as secure as encrypt-than-mac, but the code complexity of mac-then-encrypt is much smaller, only requiring the file to be read once. (even though encrypt-than-mac is more efficient compute-wise) 
	 */
    
    private static final void info(InputParams params)
    {
		File inFile = new File(params.getInputFile());
		
		//Ensure that the input file actually exists
		if(!inFile.exists() || !inFile.isFile()) {
			System.out.println("File " + inFile.toString() + " doesn't exist.");
			System.exit(0);
		}
		
		try(FileInputStream fis = new FileInputStream(inFile))
		{
			if(fis.read() != 0x09) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			int blocksize = fis.read();
			int keysize = fis.read();
			
			int algorithmLen = fis.read();
			byte[] bytes = new byte[algorithmLen];
			if(algorithmLen != (fis.read(bytes))) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			String algorithm = new String(bytes);
			
			int cipherLen = fis.read();
			bytes = new byte[cipherLen];
			if(cipherLen != (fis.read(bytes))) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			String cipher = new String(bytes);
			
			byte[] encSalt = new byte[16];
			byte[] macSalt = new byte[16];
			byte[] IV = new byte[blocksize];
			byte[] mac = new byte[32];
			
			fis.read(encSalt);
			fis.read(macSalt);
			fis.read(IV);
			fis.read(mac);
			
			System.out.println("Encrypted File Detected: ");
			System.out.println("Encryption type: " + algorithm + " | " + cipher);
			System.out.println("Key Size: " + (keysize * 8));
			System.out.println("Cipher Salt: " + Base64.getEncoder().encodeToString(encSalt));
			System.out.println("MAC Salt: " + Base64.getEncoder().encodeToString(macSalt));
			System.out.println("IV: " + Base64.getEncoder().encodeToString(IV));
			System.out.println("MAC: " + Base64.getEncoder().encodeToString(mac));
		} catch (IOException e) {
			System.out.println("File I/O Error encountered. Insufficient permissions/specified directory?");
			System.out.println("...or perhaps the file format is not valid?");
			System.out.println("Error: " + e.getMessage());
			System.exit(0);
		}
    }
    
    private static final void enc(InputParams params)
    {
    	try {
    		File inFile = new File(params.getInputFile());
    		File outFile = new File(params.getOutputFile());
    		
    		//Ensure that the input file actually exists
    		if(!inFile.exists() || !inFile.isFile()) {
    			System.out.println("File " + inFile.toString() + " doesn't exist.");
    			System.exit(0);
    		}
    		
    		//If the output file exists, check with the user before overwriting
    		if(outFile.exists()) {
    			System.out.println("File " + outFile + " already exists. Do you want to overwrite? (Y/N): ");
    			try {
					char c = (char) System.in.read();
					if(c != 'Y' && c != 'y')
						System.exit(0);
				} catch (IOException e) {
					System.exit(0);
				}
    		}
    		
    		outFile.createNewFile();
    		
    		//Rand for IV, Salt generation
        	SecureRandom rand = new SecureRandom();
        	
        	//All the variables we'll need to generate keys and initialize our primitives
        	byte[] IV = new byte[params.getCryptParams().getBlocksize()];
        	byte[] encSalt = new byte[16];
        	byte[] macSalt = new byte[16];
        	byte[] key;
        	byte[] macKey;
        	
        	//Generate IV, salts
        	rand.nextBytes(IV);
        	rand.nextBytes(encSalt);
        	rand.nextBytes(macSalt);
        	
        	//Derive the keys for the cipher and the MAC using the two salts
        	//Technically, I could have made one chonk key and split it in half
        	//This is clearer and just as secure
			key = CryptUtil.keyFromPassword(params.getCryptParams().getKeysize(), encSalt, params.getKey());
			macKey = CryptUtil.keyFromPassword(32, macSalt, params.getKey());
			
			//Generate the specifications from the raw bytes
			IvParameterSpec IVSpec = new IvParameterSpec(IV);
	        SecretKeySpec keySpec = new SecretKeySpec(key, params.getCryptParams().getAlgorithm());
	        Cipher cipher = Cipher.getInstance(params.getCryptParams().getCipher());
	       
	        //Initialize the cipher
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, IVSpec);
	        
	        //Generate MAC specifications from raw bytes
	        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA256");
	        Mac mac = Mac.getInstance("HmacSHA256");
	        
	        //Initialize
	        mac.init(macKeySpec);
	        
	        //Read the entire file end feed it into the MAC
	        try(FileInputStream fis = new FileInputStream(inFile)) {
	        	final byte[] buffer = new byte[1024];
                for(int length = fis.read(buffer); length != -1; length = fis.read(buffer)){
                    mac.update(buffer, 0, length);
                }
	        }
	        
	        //Store the MAC
	        byte[] computedMAC = mac.doFinal();
	        
	        try(FileInputStream fis = new FileInputStream(inFile)) {
	        	try(FileOutputStream fos = new FileOutputStream(outFile)) {
	        		//Write the file metadata in plaintext
	        		//No need to encrypt, it contains no secrets
	        		fos.write(0x09);
	        		fos.write((byte) params.getCryptParams().getBlocksize());
	        		fos.write((byte) params.getCryptParams().getKeysize());
	        		fos.write((byte) params.getCryptParams().getAlgorithm().length());
	        		fos.write(params.getCryptParams().getAlgorithm().getBytes());
	        		fos.write((byte) params.getCryptParams().getCipher().length());
	        		fos.write(params.getCryptParams().getCipher().getBytes());
	        		fos.write(encSalt);
	        		fos.write(macSalt);
	        		fos.write(IV);
	        		fos.write(computedMAC);
	        		
	        		//For all data in the file to encrypt, encrypt and then write to the output file
		        	try(CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
		                final byte[] buffer = new byte[1024];
		                for(int length = fis.read(buffer); length != -1; length = fis.read(buffer)){
		                    cos.write(buffer, 0, length);
		                }
		        	}
	        	}
	        }
	        
	        System.out.println("File successfully encrypted.");
    	} catch (NoSuchAlgorithmException e) {
    		System.out.println("The selected cipher (" + params.getCryptParams().getAlgorithm() + "/" + params.getCryptParams().getCipher() + ") is not available on this system. Consider upgrading your JRE.");
			System.exit(0);
		} catch (InvalidKeySpecException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (InvalidKeyException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (IOException e) {
			System.out.println("File I/O Error encountered. Insufficient permissions/specified directory?");
			System.out.println("Error: " + e.getMessage());
			System.exit(0);
		}
    }
    
    private static final void dec(InputParams params)
    {
    	File inFile = new File(params.getInputFile());
    	File outFile = new File(params.getOutputFile());
		
		//Ensure that the input file actually exists
		if(!inFile.exists() || !inFile.isFile()) {
			System.out.println("File " + inFile.toString() + " doesn't exist.");
			System.exit(0);
		}
		
		if(outFile.exists()) {
			System.out.println("File " + outFile + " already exists. Do you want to overwrite? (Y/N): ");
			try {
				char c = (char) System.in.read();
				if(c != 'Y' && c != 'y')
					System.exit(0);
			} catch (IOException e) {
				System.exit(0);
			}
		}
		
		try(FileInputStream fis = new FileInputStream(inFile))
		{
			if(fis.read() != 0x09) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			
			//Read the metadata 
			
			//Cipher information
			
			int blocksize = fis.read();
			int keysize = fis.read();
			
			int algorithmLen = fis.read();
			byte[] bytes = new byte[algorithmLen];
			if(algorithmLen != (fis.read(bytes))) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			String algorithm = new String(bytes);
			
			int cipherLen = fis.read();
			bytes = new byte[cipherLen];
			if(cipherLen != (fis.read(bytes))) {
				System.out.println("Not a valid encrypted file");
				System.exit(0);
			}
			String ciphername = new String(bytes);
			
			//Salts, initialization vectors, and the MAC
			
			byte[] encSalt = new byte[16];
			byte[] macSalt = new byte[16];
			byte[] IV = new byte[blocksize];
			byte[] givenMAC = new byte[32];
			
			fis.read(encSalt);
			fis.read(macSalt);
			fis.read(IV);
			fis.read(givenMAC);
			
			//Generate the keys the same way we do with encryption
			
			byte[] key = CryptUtil.keyFromPassword(keysize, encSalt, params.getKey());
			byte[] macKey = CryptUtil.keyFromPassword(32, macSalt, params.getKey());
			
			//Generate the specifications from the raw bytes
			IvParameterSpec IVSpec = new IvParameterSpec(IV);
	        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
	        Cipher cipher = Cipher.getInstance(ciphername);
	        
	        //Initialize the cipher
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, IVSpec);
	        
	        //Generate the specifications from the raw bytes
	        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, "HmacSHA256");
	        Mac mac = Mac.getInstance("HmacSHA256");
	        
	        //Initialize the MAC
	        mac.init(macKeySpec);
	        
	        //If metadata reading was successful, overwrite the file and create a new zero-length one
	        outFile.createNewFile();
			
	        //Initialize the cipher stream from the remaining file data
	        //For every byte we read, write it to the target file, as well as feed it into the MAC
	        try(CipherInputStream cis = new CipherInputStream(fis, cipher)) {
	        	try(FileOutputStream fos = new FileOutputStream(outFile)) {
	        		final byte[] buffer = new byte[1024];
	                for(int length = cis.read(buffer); length != -1; length = cis.read(buffer)){
	                    fos.write(buffer, 0, length);
	                    mac.update(buffer, 0, length);
	                }
	        	}
	        }
	        
	        //Compute the MAC
	        byte[] computedMAC = mac.doFinal();
	        
	        //If the MACs aren't equal, report decryption failure, delete the file, and exit
	        if(!Arrays.equals(givenMAC, computedMAC)) {
	        	System.out.println("Decrypted file didn't pass verification. Either your password was incorrect, or the file has been corrupted.");
	        	outFile.delete();
	        	System.exit(0);
	        }
	        
	        System.out.println("Successfully decrypted file.");
		} catch (IOException e) {
			if(e.getCause() != null && e.getCause() instanceof BadPaddingException) {
				System.out.println("Decrypted file didn't pass verification. Either your password was incorrect, or the file has been corrupted.");
	        	outFile.delete();
			} else {
				System.out.println("File I/O Error encountered. Insufficient permissions/specified directory?");
				System.out.println("...or perhaps the file format is not valid?");
				System.out.println("Error: " + e.getMessage());
			}
			System.exit(0);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("The cipher to decrypt the file is not available on this system. Consider upgrading your JRE.");
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (InvalidKeySpecException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (InvalidKeyException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Internal error in the application. Likely a programming bug.");
			System.exit(0);
		}
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
    		CryptParams params = new CryptParams(DEFAULT_ALGORITHM, DEFAULT_CIPHER, 16, 16);
    		if(type == CommandType.ENC && args.length == 5) {
    			start = 2;
    		}
    		char[] pass = args[start];
    		String inFile = new String(args[start + 1]);
    		String outFile = new String(args[start + 2]);
    		return new InputParams(type, params, pass, inFile, outFile);
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
    	
    	private final CryptParams params;
    	
    	private final char[] key;
    	
    	private final String inputFile, outputFile;
    	
    	public InputParams(CommandType encDec, CryptParams params, char[] key, String inputFile, String outputFile)
    	{
    		this.type = encDec;
    		this.params = params;
    		this.key = key;
    		this.inputFile = inputFile;
    		this.outputFile = outputFile;
    	}
    	
    	public InputParams(CommandType info, String inputFile)
    	{
    		this.type = info;
    		this.inputFile = inputFile;
    		this.outputFile = null;
    		this.params = null;
    		this.key = null;
    	}

		/**
		 * @return the type
		 */
		public CommandType getType() {
			return type;
		}

		/**
		 * @return the algorithm parameters
		 */
		public CryptParams getCryptParams() {
			if(type == CommandType.INFO)
				throw new IllegalStateException("Attempted to call getCryptParams on an INFO command");
			if(type == CommandType.DEC)
				throw new IllegalStateException("Attempted to call getCryptParams on an DEC command");
			return this.params;
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
    
    public static final class CryptParams
    {
    	private final String algorithm, cipher;
    	
    	private final int blocksize, keysize;

		/**
		 * @param algorithm
		 * @param cipher
		 * @param blocksize
		 * @param keysize
		 */
		public CryptParams(String algorithm, String cipher, int blocksize, int keysize) {
			this.algorithm = algorithm;
			this.cipher = cipher;
			this.blocksize = blocksize;
			this.keysize = keysize;
		}

		/**
		 * @return the algorithm
		 */
		public String getAlgorithm() {
			return algorithm;
		}

		/**
		 * @return the cipher
		 */
		public String getCipher() {
			return cipher;
		}

		/**
		 * @return the blocksize
		 */
		public int getBlocksize() {
			return blocksize;
		}

		/**
		 * @return the keysize
		 */
		public int getKeysize() {
			return keysize;
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
    	@SuppressWarnings("unused")
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
    	
    	public static final char[][] toCharArrayArray(String[] array)
    	{
    		char[][] arr = new char[array.length][];
    		for(int i = 0; i < array.length; i++)
    			arr[i] = array[i].toCharArray();
    		return arr;
    	}
    	
    }

    private static final class CryptUtil {
    	
    	//For a command line file encryption utility, fast access isn't important. High iteration count will add an extra layer of security
    	public static final int ITERATION_COUNT = 1000 * 128;
    	public static final byte[] PEPPER = Util.fromHex("8fad0183aa844319b69b8a15470e7ace".toCharArray());
    	
    	public static final byte[] keyFromPassword(int keyBytes, byte[] salt, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException
    	{
    		byte[] combined = new byte[PEPPER.length + salt.length];
    		System.arraycopy(PEPPER, 0, combined, 0, PEPPER.length);
    		System.arraycopy(salt, 0, combined, PEPPER.length, salt.length);
    		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    		PBEKeySpec spec = new PBEKeySpec(password, combined, ITERATION_COUNT, keyBytes * 8);
    		SecretKey key = factory.generateSecret(spec);
    		return key.getEncoded();
    	}
    	
    	/**
    	 * Wipes a string in memory.
    	 * From: https://konstantinpavlov.net/blog/2015/08/01/secure-java-coding-best-practices/
    	 * @param toWipe
    	 */
    	public static void wipeString(String toWipe) {
    	    try {
    	        final Field stringValue = String.class.getDeclaredField("value");
    	        stringValue.setAccessible(true);
    	        final Object val = stringValue.get(toWipe);
    	        if(val instanceof byte[]) {
    	            Arrays.fill((byte[]) val, (byte)0); // in case of compact string in Java 9+
    	        } else {
    	            Arrays.fill((char[]) val, '\u0000');
    	        }
    	    } catch (NoSuchFieldException | IllegalAccessException e) {
    	        throw new Error("Can't wipe string data");
    	    }
    	}
    	
    }
}