/**
 * AndroidBackup.java
 *
 * Copyright (c) Nikolay Elenkov
 */
package org.nick.abe;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Implementation of processing Android backup files.<br>
 * <br>
 * mostly lifted off com.android.server.BackupManagerService.java
 * 
 * @author Nikolay Elenkov
 */
public final class AndroidBackup {
	private static final String BACKUP_FILE_HEADER_MAGIC = "ANDROID BACKUP\n";
	private static final int BACKUP_FILE_VERSION = 1;
	private static final String ALGO_NAME = "AES";
	private static final String CHARSET = "UTF-8";
	private static final String ENCRYPTION_MECHANISM = "AES/CBC/PKCS5Padding";
	private static final int PBKDF2_HASH_ROUNDS = 10000;
	private static final int PBKDF2_KEY_SIZE = 256; // bits
	private static final int MASTER_KEY_SIZE = 256; // bits
	private static final int PBKDF2_SALT_SIZE = 512; // bits
	private static final String ENCRYPTION_ALGORITHM_NAME = "AES-256";
	private static final int BYTESIZE = 8;
	private static final int BYTESINKBYTE = 1024;
	private static final int HEADERSIZE = 1024;
	private static final int MARKBYTES = 100;
	private static final int BLOB_PADDING = 3;
	private static final int LINESIZE = 80;
	private static final int RADIX_HEX = 16;
	private static final int OUT_BUFFER_SIZE = 10 * BYTESINKBYTE;
	private boolean isDebug = false;
	private static final SecureRandom SEC_RANDOM = new SecureRandom();

	/** Default constructor. */
	public AndroidBackup() {
		isDebug = false;
	}

	/**
	 * Default constructor.
	 * 
	 * @param pDebug
	 *          Be more verbose
	 */
	public AndroidBackup(final boolean pDebug) {
		isDebug = pDebug;
	}

	/**
	 * Extract given file to tar archive.
	 * 
	 * @param backupFilename
	 *          backup file name (input)
	 * @param outputFilename
	 *          archive file name (output)
	 * @param password
	 *          backup password - can be null if backup is not password protected
	 */
	public void extractAsTar(final String backupFilename, final String outputFilename, final String password) {
		try {
			stdOut("Opening backup file: " + backupFilename);
			InputStream rawInStream = new FileInputStream(backupFilename);
			CipherInputStream cipherStream = null;
			String magic = readHeaderLine(rawInStream); // 1
			if (isDebug) {
				stdOut("Magic: " + magic);
			}
			String version = readHeaderLine(rawInStream); // 2
			if (isDebug) {
				stdOut("Version: " + version);
			}
			if (BACKUP_FILE_VERSION != Integer.parseInt(version)) {
				throw new IllegalArgumentException("Don't know how to process version " + version);
			}
			String compressed = readHeaderLine(rawInStream); // 3
			boolean isCompressed = Integer.parseInt(compressed) == 1;
			if (isDebug) {
				stdOut("Compressed: " + compressed);
			}
			String encryptionAlg = readHeaderLine(rawInStream); // 4
			if (isDebug) {
				stdOut("Algorithm: " + encryptionAlg);
			}
			boolean isEncrypted = false;
			if (encryptionAlg.equals(ENCRYPTION_ALGORITHM_NAME)) {
				isEncrypted = true;
				if (password == null || "".equals(password)) {
					throw new IllegalArgumentException("Backup encrypted but password not specified");
				}
				String userSaltHex = readHeaderLine(rawInStream); // 5
				byte[] userSalt = hexToByteArray(userSaltHex);
				if (userSalt.length != PBKDF2_SALT_SIZE / BYTESIZE) {
					throw new IllegalArgumentException("Invalid salt length: " + userSalt.length);
				}
				String ckSaltHex = readHeaderLine(rawInStream); // 6
				byte[] ckSalt = hexToByteArray(ckSaltHex);
				int rounds = Integer.parseInt(readHeaderLine(rawInStream)); // 7
				String userIvHex = readHeaderLine(rawInStream); // 8
				String masterKeyBlobHex = readHeaderLine(rawInStream); // 9
				// decrypt the master key blob
				Cipher c = Cipher.getInstance(ENCRYPTION_MECHANISM);
				// XXX we don't support non-ASCII passwords
				SecretKey userKey = buildPasswordKey(password, userSalt, rounds, false);
				byte[] initVector = hexToByteArray(userIvHex);
				IvParameterSpec ivSpec = new IvParameterSpec(initVector);
				c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(userKey.getEncoded(), ALGO_NAME), ivSpec);
				byte[] mkCipher = hexToByteArray(masterKeyBlobHex);
				byte[] mkBlob = c.doFinal(mkCipher);
				// first, the master key IV
				int offset = 0;
				int len = mkBlob[offset++];
				initVector = Arrays.copyOfRange(mkBlob, offset, offset + len);
				if (isDebug) {
					stdOut("IV: " + toHex(initVector));
				}
				offset += len;
				// then the master key itself
				len = mkBlob[offset++];
				byte[] mk = Arrays.copyOfRange(mkBlob, offset, offset + len);
				if (isDebug) {
					stdOut("MK: " + toHex(mk));
				}
				offset += len;
				// and finally the master key checksum hash
				len = mkBlob[offset++];
				byte[] mkChecksum = Arrays.copyOfRange(mkBlob, offset, offset + len);
				if (isDebug) {
					stdOut("MK checksum: " + toHex(mkChecksum));
				}
				// now validate the decrypted master key against the checksum
				// pre-4.4
				byte[] calculatedCk = makeKeyChecksum(mk, ckSalt, rounds, false);
				stdOut("Calculated MK checksum (pre-4.4): " + toHex(calculatedCk));
				if (!Arrays.equals(calculatedCk, mkChecksum)) {
					stdOut("pre-4.4 MK checksum does not match");
					// try 4.4 variant
					calculatedCk = makeKeyChecksum(mk, ckSalt, rounds, true);
					stdOut("Calculated MK checksum (4.4+): " + toHex(calculatedCk));
				}
				if (Arrays.equals(calculatedCk, mkChecksum)) {
					ivSpec = new IvParameterSpec(initVector);
					c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(mk, ALGO_NAME), ivSpec);
					// Only if all of the above worked properly will 'result' be
					// assigned
					cipherStream = new CipherInputStream(rawInStream, c);
				}
			}
			if (isEncrypted && cipherStream == null) {
				throw new IllegalStateException("Invalid password or master key checksum.");
			}
			InputStream baseStream = isEncrypted ? cipherStream : rawInStream;
			InputStream in = isCompressed ? new InflaterInputStream(baseStream) : baseStream;
			FileOutputStream out = null;
			stdOut("Writing to file: " + outputFilename);
			try {
				out = new FileOutputStream(outputFilename);
				byte[] buff = new byte[OUT_BUFFER_SIZE];
				int read = -1;
				long totalRead = 0;
				while ((read = in.read(buff)) > 0) {
					out.write(buff, 0, read);
					if (isDebug) {
						totalRead += read;
						if (totalRead % MARKBYTES * BYTESINKBYTE == 0) {
							stdOut(totalRead + " bytes read");
						}
					}
				}
				stdOut("Writing complete.");
			} finally {
				if (in != null) {
					in.close();
				}
				if (out != null) {
					out.flush();
					out.close();
				}
				if (baseStream != null) {
					baseStream.close();
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Create Android backup file from tar archive.
	 * 
	 * @param tarFilename
	 *          archive file as input
	 * @param backupFilename
	 *          backup file as output
	 * @param password
	 *          password used for encryption (if null, no password is used)
	 * @param isKitKat
	 *          selecte wheter the archive should be KitKat compatible
	 */
	public void packTar(final String tarFilename, final String backupFilename, final String password,
			final boolean isKitKat) {
		boolean encrypting = password != null && !"".equals(password);
		boolean compressing = true;
		StringBuilder headerbuf = new StringBuilder(HEADERSIZE);
		headerbuf.append(BACKUP_FILE_HEADER_MAGIC);
		headerbuf.append(BACKUP_FILE_VERSION); // integer, no trailing \n
		headerbuf.append(compressing ? "\n1\n" : "\n0\n");
		OutputStream out = null;
		FileInputStream in = null;
		try {
			stdOut("Opening archive file: " + tarFilename);
			in = new FileInputStream(tarFilename);
			stdOut("Opening backup file: " + backupFilename);
			FileOutputStream ofstream = new FileOutputStream(backupFilename);
			OutputStream finalOutput = ofstream;
			// Set up the encryption stage if appropriate, and emit the correct header
			if (encrypting) {
				ofstream.close();
				finalOutput = emitAesBackupHeader(headerbuf, finalOutput, password, isKitKat);
			} else {
				headerbuf.append("none\n");
			}
			byte[] header = headerbuf.toString().getBytes(CHARSET);
			ofstream.write(header);
			// Set up the compression stage feeding into the encryption stage (if any)
			if (compressing) {
				Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
				// requires Java 7
				finalOutput = new DeflaterOutputStream(finalOutput, deflater, true);
			}
			out = finalOutput;
			byte[] buff = new byte[OUT_BUFFER_SIZE];
			int read = -1;
			int totalRead = 0;
			while ((read = in.read(buff)) > 0) {
				out.write(buff, 0, read);
				if (isDebug) {
					totalRead += read;
					if (totalRead % MARKBYTES * BYTESINKBYTE == 0) {
						stdOut(totalRead + " bytes written");
					}
				}
			}
			stdOut("Creating backup file complete.");
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (out != null) {
				try {
					out.flush();
					out.close();
				} catch (IOException e) {
					/* ignore */
				}
			}
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					/* ignore */
				}
			}
		}
	}

	/**
	 * @param bits
	 *          Number of bits
	 * @return Creates random bytes
	 */
	private byte[] randomBytes(final int bits) {
		byte[] array = new byte[bits / BYTESIZE];
		SEC_RANDOM.nextBytes(array);
		return array;
	}

	/**
	 * Create encrypted stream.
	 * 
	 * @param headerbuf
	 *          Header buffer
	 * @param ofstream
	 *          Output stream
	 * @param encryptionPassword
	 *          Encryption password
	 * @param useUtf8
	 *          should be UTF-8 used instead of plain ASCII
	 * @return Encrypted stream
	 * @throws Exception
	 *           if encryption invocation failed or creating data structure failed
	 */
	private OutputStream emitAesBackupHeader(final StringBuilder headerbuf, final OutputStream ofstream,
			final String encryptionPassword, final boolean useUtf8) throws Exception {
		// User key will be used to encrypt the master key.
		byte[] newUserSalt = randomBytes(PBKDF2_SALT_SIZE);
		SecretKey userKey = buildPasswordKey(encryptionPassword, newUserSalt, PBKDF2_HASH_ROUNDS, useUtf8);
		// the master key is random for each backup
		byte[] masterPw = new byte[MASTER_KEY_SIZE / BYTESIZE];
		SEC_RANDOM.nextBytes(masterPw);
		byte[] checksumSalt = randomBytes(PBKDF2_SALT_SIZE);
		// primary encryption of the datastream with the random key
		Cipher c = Cipher.getInstance(ENCRYPTION_MECHANISM);
		SecretKeySpec masterKeySpec = new SecretKeySpec(masterPw, ALGO_NAME);
		c.init(Cipher.ENCRYPT_MODE, masterKeySpec);
		OutputStream finalOutput = new CipherOutputStream(ofstream, c);
		// line 4: name of encryption algorithm
		headerbuf.append(ENCRYPTION_ALGORITHM_NAME);
		headerbuf.append('\n');
		// line 5: user password salt [hex]
		headerbuf.append(toHex(newUserSalt));
		headerbuf.append('\n');
		// line 6: master key checksum salt [hex]
		headerbuf.append(toHex(checksumSalt));
		headerbuf.append('\n');
		// line 7: number of PBKDF2 rounds used [decimal]
		headerbuf.append(PBKDF2_HASH_ROUNDS);
		headerbuf.append('\n');
		// line 8: IV of the user key [hex]
		Cipher mkC = Cipher.getInstance(ENCRYPTION_MECHANISM);
		mkC.init(Cipher.ENCRYPT_MODE, userKey);
		byte[] initVector = mkC.getIV();
		headerbuf.append(toHex(initVector));
		headerbuf.append('\n');
		// line 9: master IV + key blob, encrypted by the user key [hex]. Blob
		// format:
		// [byte] IV length = Niv
		// [array of Niv bytes] IV itself
		// [byte] master key length = Nmk
		// [array of Nmk bytes] master key itself
		// [byte] MK checksum hash length = Nck
		// [array of Nck bytes] master key checksum hash
		//
		// The checksum is the (master key + checksum salt), run through the
		// stated number of PBKDF2 rounds
		initVector = c.getIV();
		byte[] mk = masterKeySpec.getEncoded();
		byte[] checksum = makeKeyChecksum(masterKeySpec.getEncoded(), checksumSalt, PBKDF2_HASH_ROUNDS, useUtf8);
		ByteArrayOutputStream blob = new ByteArrayOutputStream(initVector.length + mk.length + checksum.length
				+ BLOB_PADDING);
		DataOutputStream mkOut = new DataOutputStream(blob);
		mkOut.writeByte(initVector.length);
		mkOut.write(initVector);
		mkOut.writeByte(mk.length);
		mkOut.write(mk);
		mkOut.writeByte(checksum.length);
		mkOut.write(checksum);
		mkOut.flush();
		byte[] encryptedMk = mkC.doFinal(blob.toByteArray());
		headerbuf.append(toHex(encryptedMk));
		headerbuf.append('\n');
		return finalOutput;
	}

	/**
	 * @param bytes
	 *          Input bytes
	 * @return Convert input bytes to hex format
	 */
	private String toHex(final byte[] bytes) {
		StringBuffer buff = new StringBuffer();
		for (byte b : bytes) {
			buff.append(String.format("%02X", b));
		}
		return buff.toString();
	}

	/**
	 * Get one line from header.
	 * 
	 * @param in
	 *          Header as input stream
	 * @return one line from header stream
	 * @throws IOException
	 *           if read failed
	 */
	private String readHeaderLine(final InputStream in) throws IOException {
		int c;
		StringBuilder buffer = new StringBuilder(LINESIZE);
		while ((c = in.read()) >= 0) {
			if (c == '\n') {
				// consume and discard the newlines
				break;
			}
			buffer.append((char) c);
		}
		return buffer.toString();
	}

	/**
	 * @param digits
	 *          Input hex string
	 * @return Converted hex values to byte values
	 */
	private byte[] hexToByteArray(final String digits) {
		final int bytes = digits.length() / 2;
		if (2 * bytes != digits.length()) {
			throw new IllegalArgumentException("Hex string must have an even number of digits");
		}
		byte[] result = new byte[bytes];
		for (int i = 0; i < digits.length(); i += 2) {
			result[i / 2] = (byte) Integer.parseInt(digits.substring(i, i + 2), RADIX_HEX);
		}
		return result;
	}

	/**
	 * Create a key checksum.
	 * 
	 * @param pwBytes
	 *          Master key bytes
	 * @param salt
	 *          Salt
	 * @param rounds
	 *          Rounds
	 * @param useUtf8
	 *          Use UTF-8 instead of US ASCII
	 * @return Created checksum
	 */
	private byte[] makeKeyChecksum(final byte[] pwBytes, final byte[] salt, final int rounds, final boolean useUtf8) {
		if (isDebug) {
			stdOut("key bytes: " + toHex(pwBytes));
			stdOut("salt bytes: " + toHex(salt));
		}
		char[] mkAsChar = new char[pwBytes.length];
		for (int i = 0; i < pwBytes.length; i++) {
			mkAsChar[i] = (char) pwBytes[i];
		}
		if (isDebug) {
			stdOut("MK as string: [" + new String(mkAsChar) + "]");
		}
		Key checksum = buildCharArrayKey(mkAsChar, salt, rounds, useUtf8);
		if (isDebug) {
			stdOut("Key format: " + checksum.getFormat());
		}
		return checksum.getEncoded();
	}

	/**
	 * Create master key.
	 * 
	 * @param pwArray
	 *          Master key bytes
	 * @param salt
	 *          Salt
	 * @param rounds
	 *          Rounds
	 * @param useUtf8
	 *          Use UTF-8 instead of US ASCII
	 * @return Sekret key
	 */
	private SecretKey buildCharArrayKey(final char[] pwArray, final byte[] salt, final int rounds, final boolean useUtf8) {
		// Original code from BackupManagerService
		// this produces different results when run with Sun/Oracale Java SE
		// which apparently treats password bytes as UTF-8 (16?)
		// (the encoding is left unspecified in PKCS#5)
		// try {
		// SecretKeyFactory keyFactory = SecretKeyFactory
		// .getInstance("PBKDF2WithHmacSHA1");
		// KeySpec ks = new PBEKeySpec(pwArray, salt, rounds, PBKDF2_KEY_SIZE);
		// return keyFactory.generateSecret(ks);
		// } catch (InvalidKeySpecException e) {
		// throw new RuntimeException(e);
		// } catch (NoSuchAlgorithmException e) {
		// throw new RuntimeException(e);
		// } catch (NoSuchProviderException e) {
		// throw new RuntimeException(e);
		// }
		// return null;
		return androidPBKDF2(pwArray, salt, rounds, useUtf8);
	}

	/**
	 * Create master key.
	 * 
	 * @param pwArray
	 *          Master key bytes
	 * @param salt
	 *          Salt
	 * @param rounds
	 *          Rounds
	 * @param useUtf8
	 *          Use UTF-8 instead of US ASCII
	 * @return Sekret key
	 */
	private SecretKey androidPBKDF2(final char[] pwArray, final byte[] salt, final int rounds, final boolean useUtf8) {
		PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
		// Android treats password bytes as ASCII, which is obviously
		// not the case when an AES key is used as a 'password'.
		// Use the same method for compatibility.
		// Android 4.4 however uses all char bytes
		// useUtf8 needs to be true for KitKat
		byte[] pwBytes = useUtf8 ? PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pwArray) : PBEParametersGenerator
				.PKCS5PasswordToBytes(pwArray);
		generator.init(pwBytes, salt, rounds);
		KeyParameter params = (KeyParameter) generator.generateDerivedParameters(PBKDF2_KEY_SIZE);
		return new SecretKeySpec(params.getKey(), ALGO_NAME);
	}

	/**
	 * Create password key.
	 * 
	 * @param pw
	 *          Password
	 * @param salt
	 *          Salt
	 * @param rounds
	 *          Rounds
	 * @param useUtf8
	 *          Use UTF-8 instead of US ASCII
	 * @return Created secret key
	 */
	private SecretKey buildPasswordKey(final String pw, final byte[] salt, final int rounds, final boolean useUtf8) {
		return buildCharArrayKey(pw.toCharArray(), salt, rounds, useUtf8);
	}

	/**
	 * Show given text to stdout.
	 * 
	 * @param text
	 *          Text to display
	 */
	public static void stdOut(final String text) {
		System.out.println(text);
	}
}
