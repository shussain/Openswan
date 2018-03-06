#ifndef __seam_timer_c__
#define __seam_timer_c__

#ifndef WANT_TIMER

/* timer.c SEAM */
void timer_list(void) {}

void event_schedule(enum event_type type, time_t tm, struct state *st) {
  if (st == NULL)
    DBG_log("inserting event %s, timeout in %lu second"
            , enum_show(&timer_event_names, type), (unsigned long)tm);
  else
    DBG_log("inserting event %s, timeout in %lu seconds for #%lu"
            , enum_show(&timer_event_names, type), (unsigned long)tm
            , st->st_serialno);
}
void _delete_dpd_event(struct state *st, const char *file, int lineno) {}
void delete_event(struct state *st) {}

#endif




#endif
