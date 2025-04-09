#ifndef _OBJECT_FUZZ_H
#define _OBJECT_FUZZ_H

#ifdef CONFIG_OBJECT_FUZZ

void object_fuzz_event_hook(char *, int);
void object_fuzz_access_user_hook(const void *, uint64_t);

#endif

#endif // _OBJECT_FUZZ_H