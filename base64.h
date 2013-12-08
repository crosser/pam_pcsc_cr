/*
This is an addition to the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

/*
  Modified by Eugene Crosser to fit pam_pcsc_cr project, 2013
*/

#ifndef BASE64_H
#define BASE64_H

int b64_encode(const char *src, const int ssize,
		char *const b64, int *const bsize);
int b64_decode(const char *b64, char *const dst, int *const dsize);

#endif /* BASE64_H */
