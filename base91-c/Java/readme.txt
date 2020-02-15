This is an implementation of the basE91 encoder and decoder in Java.

Syntax:
	java -jar base91.jar [OPTION] infile [outfile]

Options:

-d	decode a basE91 encoded file;
	all non-alphabet characters (such as newlines) are ignored

-u	leave encoder output unformatted;
	i. e., disable line wrapping after 76 characters

-h	display short help and exit

-V	output version information and exit


If no outfile is given for encoding, it defaults to `infile_b91.txt' (or to
`infile.b91' with the `-u' switch).
On decoding, the added file extension is removed to generate the name for
outfile; otherwise, if infile hasn't a default extension, the decoded data is
written to `infile.bin'.

For further information visit the basE91 home page at
http://base91.sourceforge.net/
