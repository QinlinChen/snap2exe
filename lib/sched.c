#include "sys.h"
#include "config.h"
#include "sched.h"
#include "log.h"

static int prob_scheduler(int prob)
{
    return (rand() % 100) < prob;
}

static int must_scheduler()
{
    return 1;
}

int is_time_to_snapshot(int policy)
{
    switch (policy)
    {
    case S2E_SCHED_MUST:
        return must_scheduler();
    case S2E_SCHED_PROB:
        return prob_scheduler(config.sched_prob);
    default:
        log_error("Invalid policy");
        break;
    }
    return 0;
}
