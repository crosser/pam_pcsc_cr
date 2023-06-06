#ifndef _READER_H
#define _READER_H

struct reader_ctx;
struct target_ctx;

struct reader_interface {
	char *name;
	struct reader_ctx *(*init_ctx) (void);
	int (*parse_option)(struct reader_ctx * ctx, char *key, char *val);
	int (*for_each_target)(struct reader_ctx * ctx,
			       (int *callback)(struct target_ctx * tgt,
					       void *arg), void *arg);
	void (*drop_ctx)(*struct reader_ctx * ctx);
	int (*transcieve)(struct target_ctx * tgt, uint8_t * send,
			 size_t send_size, uint8_t * recv,
			 size_t *recv_size_p);
};

#endif
