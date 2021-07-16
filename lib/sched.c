#include "sys.h"
#include "config.h"
#include "sched.h"

#include <sys/time.h>

#include "log.h"

static int prob_scheduler(int prob)
{
    return (rand() % 100) < prob;
}

static int must_scheduler()
{
    return 1;
}

static int throttle_scheduler(int interval)
{
    static long long last_time = 0; /* microseconds */

    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        log_unix_error("fail to gettimeofday");

    long long cur_time = 1000*tv.tv_sec + tv.tv_usec;
    int ok = (cur_time - last_time > interval);
    if (ok)
        last_time = cur_time;

    // log_info("sched at: %ld.%ld.   %s",
    //          tv.tv_sec, tv.tv_usec, ok ? "ok!" : "no!");
    return ok;
}

int is_time_to_snapshot(int policy)
{
    int all_policies = S2E_SCHED_MUST | S2E_SCHED_PROB | S2E_SCHED_THROTTLE;
    if ((policy & all_policies) == 0) {
        log_error("Invalid policy: %d", policy);
        return 0;
    }

    int ok = 1;

    if (policy & S2E_SCHED_MUST)
        ok &= must_scheduler();
    if (policy & S2E_SCHED_PROB)
        ok &= prob_scheduler(config.sched_prob);
    if (policy & S2E_SCHED_THROTTLE)
        ok &= throttle_scheduler(500); /* TODO: parameterize interval. */

    return ok;
}
