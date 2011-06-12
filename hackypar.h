/* Hacky parallelism
 * Ian Jackson
 * We fork, and return false !
 */

#ifndef hackympzpar_h
#define hackympzpar_h

struct site;

int hacky_par_start_failnow(void);
int hacky_par_mid_failnow(void);
void hacky_par_end(int *ok,
		   int32_t retries, uint32_t timeout,
		   bool_t (*send_msg)(struct site *st), struct site *st);

#endif /* hackympzpar_h */
