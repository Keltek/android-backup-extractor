/**
 * Main.java
 *
 * Copyright (c) Nikolay Elenkov
 */
package org.nick.abe;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Security;
import java.util.Comparator;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Main class for backup extractor.
 * 
 * @author Nikolay Elenkov
 */
public final class Main {
	private static final String VERSION_STRING = "2.0.0";
	private static final String ABE_NAME = "Android Backup Extractor";
	//
	private static E_OPERATION pOperation = null;
	private static boolean pDebug = false;
	private static String pBackupFile = null;
	private static String pArchiveFile = null;
	private static String pPassword = null;
	//
	private static Options fullOptions = null;
	//
	private static Option oHelp = new Option("h", "help", false, "display help message");
	private static Option oVersion = new Option("v", "version", false, "display version\n");

	/**
	 * Backup operations.
	 * 
	 * @author Ondrej Zima
	 * @version $Revision: 1.2 $ 5. 3. 2014
	 */
	private enum E_OPERATION {
		UNSET, UNPACK, PACK, PACKKK
	}

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
		parseCmdLine(args);
		if (pOperation == E_OPERATION.UNSET) {
			System.exit(1);
		}
		AndroidBackup ab = new AndroidBackup(pDebug);
		if (pOperation == E_OPERATION.UNPACK) {
			ab.extractAsTar(pBackupFile, pArchiveFile, pPassword);
		} else if (pOperation == E_OPERATION.PACK) {
			ab.packTar(pArchiveFile, pBackupFile, pPassword, false);
		} else if (pOperation == E_OPERATION.PACKKK) {
			ab.packTar(pArchiveFile, pBackupFile, pPassword, true);
		}
	}

	/** Display usage text. */
	private static void usage() {
		// System.out.println("Usage:");
		// System.out.println("  unpack:\tabe unpack\t<backup.ab> <backup.tar> [password]");
		// System.out.println("  pack:\t\tabe pack\t<backup.tar> <backup.ab> [password]");
		// System.out.println("  pack for 4.4:\tabe pack-kk\t<backup.tar> <backup.ab> [password]");
		//
		String header = ABE_NAME + " version " + VERSION_STRING + "\n";
		String footer = "\n";
		HelpFormatter hf = new HelpFormatter();
		hf.setOptionComparator(new Comparator<Option>() {
			private static final String OPTS_ORDER = "hvupkbtwd";

			/** {@inheritDoc} */
			public int compare(final Option o1, final Option o2) {
				return OPTS_ORDER.indexOf(o1.getOpt()) - OPTS_ORDER.indexOf(o2.getOpt());
			}
		});
		StringWriter out = new StringWriter();
		hf.printUsage(new PrintWriter(out), HelpFormatter.DEFAULT_WIDTH, "abe", fullOptions);
		hf.printHelp(HelpFormatter.DEFAULT_WIDTH, out.toString(), header, fullOptions, footer);
	}

	/** Display version string. */
	private static void version() {
		stdOut(ABE_NAME);
		stdOut("Version: " + VERSION_STRING);
	}

	/**
	 * Parse input arguments and prepare execution.
	 * 
	 * @param args
	 *          Input arguments
	 */
	private static void parseCmdLine(final String[] args) {
		pOperation = E_OPERATION.UNSET;
		fullOptions = getFullOptions();
		// Check for help or version parameter
		try {
			Options optsFirst = new Options();
			optsFirst.addOption(oHelp);
			optsFirst.addOption(oVersion);
			CommandLine clFirst = new GnuParser().parse(optsFirst, args, true);
			if (clFirst.getOptions().length > 0) {
				pOperation = E_OPERATION.UNSET;
				// Display help or version
				if (clFirst.hasOption("h")) {
					usage();
					return;
				} else {
					version();
					return;
				}
			} else {
				// Process main options
				CommandLine cmd = new GnuParser().parse(fullOptions, args);
				// Get operation
				if (cmd.hasOption("u")) {
					pOperation = E_OPERATION.UNPACK;
				} else if (cmd.hasOption("p")) {
					pOperation = E_OPERATION.PACK;
				} else if (cmd.hasOption("k")) {
					pOperation = E_OPERATION.PACKKK;
				} else {
					// No operation selected
					pOperation = E_OPERATION.UNSET;
					// usage();
				}
				// Construct arguments
				if (pOperation != E_OPERATION.UNSET) {
					pDebug = cmd.hasOption("d");
					pBackupFile = cmd.getOptionValue("b");
					pPassword = cmd.getOptionValue("w");
					pArchiveFile = cmd.getOptionValue("t");
				}
			}
		} catch (ParseException pe) {
			stdErr("Error parsing input parameters.");
			usage();
			stdErr(pe.getMessage());
			pOperation = E_OPERATION.UNSET;
		}
	}

	/**
	 * Show given text to stderr.
	 * 
	 * @param text
	 *          Text to display
	 */
	public static void stdErr(final String text) {
		System.err.println(text);
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

	/** @return Constructed full options */
	private static Options getFullOptions() {
		Options opts = new Options();
		// Options
		Option oBackupFile = new Option("b", "backup", true, "backup file to unpack");
		oBackupFile.setRequired(true);
		Option oArchiveFile = new Option("t", "archive", true, "select output archive (tar) file");
		oArchiveFile.setRequired(true);
		Option oDebug = new Option("d", "debug", false, "be more verbose");
		Option oPassword = new Option("w", "password", true, "select password for unpack/pack operation");
		Option oUnpack = new Option("u", "unpack", false, "unpack given backup.ab file");
		Option oPack = new Option("p", "pack", false, "pack given tar file");
		Option oPackkk = new Option("k", "packkk", false, "pack given tar file to backup file with KitKat compatibility");
		// Operation group
		OptionGroup ogOperation = new OptionGroup();
		ogOperation.addOption(oUnpack);
		ogOperation.addOption(oPack);
		ogOperation.addOption(oPackkk);
		ogOperation.setRequired(true);
		// Generic options
		opts.addOptionGroup(ogOperation);
		opts.addOption(oHelp);
		opts.addOption(oVersion);
		opts.addOption(oBackupFile);
		opts.addOption(oArchiveFile);
		opts.addOption(oDebug);
		opts.addOption(oPassword);
		return opts;
	}
}
