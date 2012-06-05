/* It starts a process and uses Intel's PIN to					*/
/* trace (at a Basic Block level) its execution.				*/
/*																*/
/* Dumps to a file that will be processed by IDA Pro.			*/
/* TODO: Attach to the process instead of opening it?			*/


#include "pin.H"
#include <iostream>
#include <string>



/* Global Variables */

FILE *trace;
std::vector<unsigned int> functionIntervals;
char outputFilename[] = "traceBBL.txt";


/* Command Line Switches */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", outputFilename, "specify trace filename");


/* ============================================================================== */
/* Help Message																	  */
/* ============================================================================== */

INT32 Usage()
{
	cerr <<
			"This tools produces a dynamic instruction trace.\n"
			"The trace saves only addresses of basic blocks hit\n"
			"which dramatically reduces the output size and the overhead of the tool.\n"
			"\n";

	cerr << KNOB_BASE::StringKnobSummary();

	cerr << endl;

	return -1;
}


/* ============================================================================== */
/* Auxiliary Functions															  */
/* ============================================================================== */

BOOL withinInterestingFunction(int ip)
{
	unsigned int idx = 0;

	while (idx < functionIntervals.size())
	{
		/* Check if the instruction is within the interesting function boundaries */
		if(ip >= functionIntervals[idx] && ip <= functionIntervals[idx + 1])
			return true;

		idx += 2;
	}

	return false;
}



VOID printip(VOID *ip)
{
	/* Any elaborated logging capabilities would be implemented here */
	if(withinInterestingFunction((int)ip))
	{
		fprintf(trace, "$ %p\n", ip);  // $ has no meaning, just a random token
		fflush(trace);
	}
}


/* ============================================================================== */
/* This is the meat and potatoes of the application 							  */
/* ============================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{

		INS_InsertCall(BBL_InsTail(bbl), IPOINT_BEFORE, AFUNPTR(printip),
				IARG_INST_PTR,	IARG_END);
	}
}


/* ============================================================================== */
/* Any cleanup operations after the trace go here 								  */
/* ============================================================================== */
VOID Fini(INT32 code, VOID *v)
{
	fprintf(trace, "# eof\n");
	fclose(trace);
}


/* ============================================================================== */
/* Main 																		  */
/* ============================================================================== */

int main(int argc, char *argv[])
{
	unsigned int x;


	string trace_header = string("#\n"
								 "# Basic Block Level Trace Generated By PIN\n"
								 "#\n");

	if(PIN_Init(argc, argv))
	{
		return Usage();
	}


	/* Open trace log file for writing */
	trace = fopen(KnobOutputFile.Value().c_str(), "w+");
	fprintf(trace, trace_header.c_str(), trace_header.size());


	/* ======================================================================= */
	/* I process the interesting functions file here to get the ranges.   	   */
	/* ======================================================================= */
	FILE *interestingFunctions = fopen("specific_functions_intervals.txt", "r");

	if (interestingFunctions != NULL)
	{
		char line[128];	// Fixed maximum line size (UGLY)

		while(fgets(line, sizeof(line), interestingFunctions))  // read a line
		{
			/* Tokenize the line! (split it) */
			char *token;
			token = strtok(line, "-");	// first token

			while(token != NULL)
			{
				// Convert hex string to uint32
				// Remember the values denoted by the string are in hex.
				// Therefore the 16 base at strtoul() :)
				x = strtoul(token, NULL, 16);

				/* Fill the vector */
				functionIntervals.push_back(x);

				token = strtok(NULL, "-");	// next token(s)
			}
		}
		fclose(interestingFunctions);
	}
	else
	{
		perror("specific_functions.txt"); // what happened with fopen ?
	}


	// At this point the vector functionIntervals contains the addresses
	// in the following form: [f1_start, f1_end, f2_start, f2_end, ...]


	/* Here I point PIN to my processing functions */
	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddFiniFunction(Fini, 0);

	// It never returns. Sad,
	PIN_StartProgram();

	return 0;
}
