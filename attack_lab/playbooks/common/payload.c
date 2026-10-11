/* SecLab 标准载荷：唯一行为是向指定 endpoint 建立一次 TCP 连接后退出。
 * 真实 ELF、可审计、无害；判定对象锚点。用法: payload <ip> <port> [dwell_ms]
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 8443;
    int dwell = argc > 3 ? atoi(argv[3]) : 1000;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        char mark[] = "beacon";
        write(fd, mark, sizeof(mark) - 1);
    }
    usleep(dwell * 1000);
    close(fd);

    /* 派生阶段（chain 形态）：argv[4] 起为待执行命令，由本载荷 fork/exec——
     * 进程树上后续动作归属本载荷，跨阶段归因由此成立（r11 复核整改）。 */
    if (argc > 4) {
        pid_t pid = fork();
        if (pid == 0) {
            execv("/bin/bash", (char *[]){"/bin/bash", "-c", argv[4], NULL});
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
    }
    return 0;
}
