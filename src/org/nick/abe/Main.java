/**
 * $Id: CAConstans.java,v 1.7 2013/10/25 14:21:06 ozim Exp $
 *
 * Copyright (c) Nikolay Elenkov
 */
package org.nick.abe;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Main class for backup extractor.
 * 
 * @author Nikolay Elenkov
 * @version $Revision: 1.2 $ 5. 3. 2014
 */
public final class Main {
	private static final int MAXPARLEN = 3;

	/** Hidden constructor. */
	private Main() {
		/* empty */
	}

	/**
	 * Method for executing.
	 * 
	 * @param args
	 *          Input arguments
	 */
	public static void main(final String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		if (args.length < MAXPARLEN) {
			usage();
			System.exit(1);
		}
		String mode = args[0];
		if (!"pack".equals(mode) && !"unpack".equals(mode) && !"pack-kk".equals(mode)) {
			usage();
			System.exit(1);
		}
		boolean unpack = "unpack".equals(mode);
		String backupFilename = unpack ? args[1] : args[2];
		String tarFilename = unpack ? args[2] : args[1];
		String password = null;
		if (args.length > MAXPARLEN) {
			password = args[MAXPARLEN];
		}
		if (unpack) {
			AndroidBackup.extractAsTar(backupFilename, tarFilename, password);
		} else {
			boolean isKitKat = "pack-kk".equals(mode);
			AndroidBackup.packTar(tarFilename, backupFilename, password, isKitKat);
		}
	}

	/** Display usage text. */
	private static void usage() {
		System.out.println("Usage:");
		System.out.println("  unpack:\tabe unpack\t<backup.ab> <backup.tar> [password]");
		System.out.println("  pack:\t\tabe pack\t<backup.tar> <backup.ab> [password]");
		System.out.println("  pack for 4.4:\tabe pack-kk\t<backup.tar> <backup.ab> [password]");
	}
}
