#include "../ft_traceroute.h"

const char *help_flag = "--help";

void usage_exit()
{
    printf("Usage:\n  ft_traceroute host\nOptions:\n  --help                      Read this help and exit\n");
    exit(0);
}
//just need to add some options for max wait, max ttl, n_probes and that's it
int main(int argc, char **argv)
{
    struct tr tr;
    int help_len = ft_strlen(help_flag);
    char *address;

    if (argc == 2)
    {
        if (ft_strncmp(argv[1], help_flag, help_len) == 0)
        {
            usage_exit();
        }
        address = argv[1];
    }
    else
    {
        usage_exit();
    }

    ft_bzero(&tr, sizeof(tr));
    tr.n_probes = PROBES_NUM;
    tr.max_ttl = MAX_TTL;
    tr.max_wait = MAX_WAIT;
    tr.host_address = address;

    trace_loop(&tr);
}
