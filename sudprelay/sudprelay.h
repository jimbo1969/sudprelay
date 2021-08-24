//sudprelay.h
//All this header file does is take the version number info provided in the 
//	sudprelay_config.h header, and provide some string concatenation tricks
//	that will enable us to turn the version number into a string literal that 
//	can be used by the preprocessor (or downstream).
//
#include "sudprelay_config.h"

/*
 * Concatenate preprocessor tokens A and B without expanding macro definitions
 * (however, if invoked from a macro, macro arguments are expanded).
 */
#define PPCAT_NX(A, B) A ## .B

/*
 * Concatenate preprocessor tokens A and B after macro-expanding them.
 */
#define PPCAT(A, B) PPCAT_NX(A, B)

/*
 * Turn A into a string literal without expanding macro definitions
 * (however, if invoked from a macro, macro arguments are expanded).
 */
#define STRINGIZE_NX(A) #A

/*
 * Turn A into a string literal after macro-expanding it.
 */
#define STRINGIZE(A) STRINGIZE_NX(A)

/*
 * Concatenate the whole enchilada (version number) into one string literal
 */
#define VER STRINGIZE(PPCAT(PPCAT(PPCAT(VERSION_MAJOR, VERSION_MINOR), VERSION_PATCH), VERSION_TWEAK))
