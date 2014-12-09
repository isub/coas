/* m_cAction values
	'T'	- Abnormal termination of the process. The process is terminated with all the consequences of _exit() except that the status made available to wait() and waitpid()  indicates abnormal termination by the specified signal.
	'A'	- Abnormal termination of the process. Additionally, implementation-defined abnormal termination actions, such as creation of a core file, may occur.
	'I'	- Ignore the signal.
	'S'	- Stop the process.
	'C'	- Continue the process, if it is stopped; otherwise, ignore the signal.
*/
struct SSignalDesc {
	int m_iSigCode;
	char m_cAction;
	const char *m_pszDescription;
};

struct SMainConfig {
	char	*m_pszPidFile;
	int		m_iDebug;					// Debug level
	int		m_iDCD;						// Debug Call Depth
};
