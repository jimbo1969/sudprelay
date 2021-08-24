/*sys_time.h  --  JW Aug 2021
sys/time.h is a POSIX header, not Windows
this file, plus sys_time.c, provides what is needed from that header.
*/

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif

#if defined WIN32


struct timezone
{
	int tz_minuteswest; /* minutes W of Greenwich */
	int tz_dsttime; /* type of dst correction */
} timezone;

#endif
