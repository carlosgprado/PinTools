/* This program will log every function ever hit. 			*/
/* Takes advantage of INTEL Pin's intelligence.   			*/
/* It doesn't need to know in advance the functions but		*/
/* it detects when a CALL is executed instead :)			*/
/* TODO: I'm not interested in calls to system DLLs... 		*/

#include <stdio.h>
#include <iostream>
#include <algorithm>	// used for find()
#include "pin.H"


using std::vector;
using std::find;


/* Global Variables */
FILE* LogFile;
vector<ADDRINT> loggedAddresses;
ADDRINT MAX_USER_MEM = 0x50000000;  // Somehow arbitrary, improve!



/* Command Line stuff */
KNOB<BOOL> KnobLogArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "log call arguments ");



void Fini(INT32 code, void *v)
{
	fprintf(LogFile, "# EOF\n");
	fclose(LogFile);
}



/* Auxiliary function. This is a HIT tracer, I just want to log every function ONCE */
BOOL alreadyLoggedAddresses(ADDRINT ip)
{
	if(find(loggedAddresses.begin(), loggedAddresses.end(), ip) != loggedAddresses.end())
	{
		// item IS IN vector
		return true;
	}
	else
	{
		// item is NOT in vector. Push it for the next time.
		loggedAddresses.push_back(ip);
		return false;
	}
}


/* Callbacks implementing the actual logging */
void LogCall(ADDRINT ip)
{
	/* This can be extended to fancier logging capabilities */
	if (ip >= MAX_USER_MEM || alreadyLoggedAddresses(ip))
		return;

	UINT32 *CallArg = (UINT32 *)ip;
	fprintf(LogFile, "$ %p\n", CallArg);  // $ has no meaning, just a random token
}


void LogCallAndArgs(ADDRINT ip, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	/* This can be extended to fancier logging capabilities */
	if (ip >= MAX_USER_MEM || alreadyLoggedAddresses(ip))
		return;

	UINT32 *CallArg = (UINT32 *)ip;
	/* NOTE: $ has no meaning, just a random token */
	fprintf(LogFile, "$ %p: %u %u %u\n", CallArg, arg0, arg1, arg2);
}


void LogIndirectCall(ADDRINT target, BOOL taken)
{
	if(!taken)
		return;
	else if(target >= MAX_USER_MEM || alreadyLoggedAddresses(target))
		return;

	LogCall(target);
}


void LogIndirectCallAndArgs(ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	if(!taken)
		return;
	else if(target >= MAX_USER_MEM || alreadyLoggedAddresses(target))
		return;

	LogCallAndArgs(target, arg0, arg1, arg2);
}


/* This is called every time a new instruction is encountered */
void Trace(TRACE trace, void *v)
{
	/* Do I want to log function arguments as well? */
	const BOOL log_args = KnobLogArgs.Value();


	/* Iterate through basic blocks */
	for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		/* Since a BB is single entry, single exit a possible call can only be at the end */
		INS tail = BBL_InsTail(bbl);

		if(INS_IsCall(tail))
		{
			if(INS_IsDirectBranchOrCall(tail))
			{
				/* For direct branches or calls, returns the target address */
				const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);

				if(log_args)
				{
					INS_InsertPredicatedCall(
											tail,
											IPOINT_BEFORE,
											AFUNPTR(LogCallAndArgs),		// Fn to jmp to
											IARG_ADDRINT,					// "target"'s type
											target,							// The XXX in "CALL XXX" :)
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_0 value
											0,
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_1 value
											1,
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_2 value
											2,
											IARG_END						// No more args
											);
				}
				else
				{
					INS_InsertPredicatedCall(
											tail,
											IPOINT_BEFORE,
											AFUNPTR(LogCall),		// Fn to jmp to
											IARG_ADDRINT,			// "target"'s type
											target,					// The XXX in "CALL XXX" :)
											IARG_END				// No more args
											);
				}

			}
			else
			{
				/* This is an indirect call (INS_IsBranchOrCall == True) */
				if(log_args)
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCallAndArgs),	// Fn to jmp to
									IARG_BRANCH_TARGET_ADDR,			// "target"'s type
									IARG_BRANCH_TAKEN,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_0 value
									0,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_1 value
									1,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_2 value
									2,
									IARG_END							// No more args
									);
				}
				else
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCall),	// Fn to jmp to
									IARG_BRANCH_TARGET_ADDR,	// Well... target address? :)
									IARG_BRANCH_TAKEN,			// Non zero if branch is taken
									IARG_END					// No more args
									);
				}
			}
		} // end "if INS_IsCall..."
		else
		{
				/* For the case code is not in an image but in a DLL or alike */
				RTN rtn = TRACE_Rtn(trace);

				// Trace jmp into DLLs (.idata section that is, imports)
				if(RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && SEC_Name(RTN_Sec(rtn)) == ".idata")
				{
					if(log_args)
					{
						INS_InsertCall(
										tail,
										IPOINT_BEFORE,
										AFUNPTR(LogIndirectCallAndArgs),	// Fn to jmp to
										IARG_BRANCH_TARGET_ADDR,
										IARG_BRANCH_TAKEN,
										IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_0 value
										0,
										IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_1 value
										1,
										IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_2 value
										2,
										IARG_END							// No more args
										);
					}
					else
					{
						INS_InsertCall(
										tail,
										IPOINT_BEFORE,
										AFUNPTR(LogIndirectCall),
										IARG_BRANCH_TARGET_ADDR,
										IARG_BRANCH_TAKEN,
										IARG_END
										);
					}
				}
		}
	} // end "for bbl..."
} // end "void Trace..."


/* Help message */
INT32 Usage()
{
	cerr << PIN_ERROR("Log addresses of every call ever made. Used in differential debugging.\n"
			+ KNOB_BASE::StringKnobSummary() + "\n") << endl;

	return -1;
}


/* Main function - initialize and set instrumentation callbacks */
int main(int argc, char *argv[])
{
	/* Initialize Pin with symbol capabilities */
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)) return Usage();

	LogFile = fopen("functions_log.txt", "w");

	/* Set callbacks */
	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddFiniFunction(Fini, 0);

	/* It never returns, sad :) */
	PIN_StartProgram();

	return 0;
}
