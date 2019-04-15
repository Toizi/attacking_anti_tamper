#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>

static char org_serial[] = "this_be_da_serial";
char serial[] = "vjkq]`g]fc]qgpkcn";

#pragma protect anti-tamper.on
int check_input(const char *s) {
    int len = strlen(s);
	if (len == 0)
		return -1;
    for (int i = 0; i < len; ++i) {
        if ((s[i] ^ 0x02) != serial[i])
            return -1;
    }
    return 0;
}

#pragma protect anti-tamper.on
int main(int argc, const char **argv) {
    char buf[21];
    scanf("%20s", buf);
    buf[20] = 0;

    int ret = check_input(buf);
    if (ret == 0) {
        printf("success\n");
		return 0;
    } else {
        printf("failed\n");
		return -1;
    }
}
