#include <signal.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>

#include "ops_log.h"
#include "ops_net.h"
#include "ops_shell.h"
#include "main.h"

struct uds_session_t {
    uint8_t is_used;
    uint8_t magic;
    uint16_t index;
    struct sockaddr_un cli_addr;
    socklen_t cli_addr_len;
} __attribute__ ((packed));

//static int socket_fd = -1;
static struct uds_session_t session[MAX_CLIENT_SHELL];

struct shell_session_t {
    pid_t pid;
    uint8_t pty_name[MAX_PTY_NAME];
    int pty_master;
    struct shell_cmd_t cmd;
    uint8_t is_used;
} __attribute__ ((packed));
static struct shell_session_t shell_session_list[MAX_SHELL_INSTANCE];

static int parse(uint8_t* strings, uint8_t strings_size, char **ptrs)
{
	uint16_t ptr_idx = 0;
	uint8_t found_sep = 0;
	ptrs[ptr_idx++] = &strings[0];
	for(int i=0;i<strings_size;i++) {
		if(found_sep) {
			found_sep = 0;
			ptrs[ptr_idx++] = &strings[i];
		}
		if(strings[i] == ' ') {
			strings[i] = 0x0;
			found_sep = 1;
		}
	}
	ptrs[ptr_idx] = NULL;
	return ptr_idx;
}

static void sig_fork(int signo)
{
    struct ops_log_t *log = get_log_instance();
    struct shell_session_t *shell_instance = NULL;
    struct shell_cmd_t *shell_cmd = NULL;

    for(int j=0;j<MAX_SHELL_INSTANCE;j++) {
        shell_instance = &shell_session_list[j];
        if(shell_instance->is_used) {
            shell_cmd = &shell_instance->cmd;
            int status = -1;
            int ret = waitpid (shell_instance->pid, &status, WNOHANG);
            if(ret < 0) {
                log->error(0xFF, __FILE__, __func__, __LINE__, "waitpid %d error %d\n", shell_instance->pid, ret);
                //int pty_master = shell_cmd->pty_master;
                //memset(shell_cmd, 0, sizeof(struct shell_cmd_t));
                //shell_cmd->pty_master = 0;
                //shell_cmd->status = SHELL_STATUS_UNKNOWN;
                //if(pty_master > 0) 
                //    close(pty_master);
                shell_instance->is_used = 0;
                continue;
            }
            //log->error(0xFF, __FILE__, __func__, __LINE__, "Check Status %d, %d, %d, %x\n", j, status, shell_instance->pid, shell_cmd->status);
            if (WIFEXITED(status)) {
                log->error(0xFF, __FILE__, __func__, __LINE__, "child[%d] exited normal exit status=%d\n", shell_instance->pid, WEXITSTATUS(status));
            }
            if (WIFSIGNALED(status)) {
                log->error(0xFF, __FILE__, __func__, __LINE__, "child[%d] exited abnormal signal number=%d\n", shell_instance->pid, WTERMSIG(status));
            }
            if (WIFSTOPPED(status)) {
                log->error(0xFF, __FILE__, __func__, __LINE__, "child[%d] stoped signal number=%d\n", shell_instance->pid, WSTOPSIG(status));
            }
            if(shell_cmd->action == SHELL_ACTION_TERMINATE) {
                //int pty_master = shell_cmd->pty_master;
                //memset(shell_cmd, 0, sizeof(struct shell_cmd_t));
                //shell_cmd->pty_master = 0;
                //shell_cmd->status = SHELL_STATUS_UNKNOWN;
                //if(pty_master > 0) 
                //    close(pty_master);
                shell_instance->is_used = 0;
            }
        }
    }
}

int main(int argc, char** argv)
{
    struct ops_net_t *net = get_net_instance();
    struct ops_log_t *log = get_log_instance();

    struct msg_t req;
    struct msg_t res;
    int i = 0;
    int j = 0;
    uint8_t magic = 0;
#define MAX_PTR		24
    char* ptr[MAX_PTR];
    struct uds_session_t *uds = NULL;
    struct shell_session_t *shell_instance = NULL;
    struct shell_cmd_t *req_cmd = (struct shell_cmd_t*)&req.data;
    struct shell_cmd_t *res_cmd = (struct shell_cmd_t*)&res.data;
    struct shell_cmd_t *shell_cmd = NULL;
    uint8_t found_instance = 0;

    signal (SIGCHLD, sig_fork);
    for(i=0;i<MAX_CLIENT_SHELL;i++) {
        uds = &session[i];
	memset(uds, 0, sizeof(struct uds_session_t));
	uds->is_used = 0;
	uds->cli_addr_len = sizeof(struct sockaddr_un);
	uds->index = i;
    }
    for(j=0;j<MAX_SHELL_INSTANCE;j++) {
        shell_instance = &shell_session_list[j];
	shell_cmd = &shell_instance->cmd;
	memset(shell_instance, 0, sizeof(struct shell_session_t));
	//shell_cmd->pty_master = 0;
	shell_cmd->action = SHELL_ACTION_UNKNOWN;
    }
    uds = NULL;
    shell_instance = NULL;
    shell_cmd = NULL;

    int socket_fd = net->uds_server_create(SOCKET_PATH_SHELL);
    if(socket_fd < 0) {
        log->error(0xFF, __FILE__, __func__, __LINE__, "bind socket error");
        return 1;
    }

    while(1) {
        for(i=0;i<MAX_CLIENT_SHELL;i++) {
            uds = &session[i];
            if(uds->is_used) {
                continue;
            } else {
                uds->is_used = 1;
                magic += 1;
                memset(&uds->cli_addr, 0, sizeof(struct sockaddr_un));
		memset(req_cmd, 0, sizeof(struct shell_cmd_t));
		memset(res_cmd, 0, sizeof(struct shell_cmd_t));

                uds->magic = magic;
                net->uds_server_recv(socket_fd, &req, &uds->cli_addr, &uds->cli_addr_len);
                for(j=0;j<MAX_SHELL_INSTANCE;j++) {
                    shell_instance = &shell_session_list[j];
                    shell_cmd = &shell_instance->cmd;

		    if(shell_instance->is_used) {
		    } else {
                            // BEGIN: re-init values after shell instance close
			    if(shell_instance->pty_master > 0) {
				    close(shell_instance->pty_master);
				    shell_instance->pty_master = 0;
				    shell_instance->pid = 0;
				    memset(shell_instance->pty_name, 0, MAX_PTY_NAME);

				    memset(shell_cmd, 0, sizeof(struct shell_cmd_t));
				    shell_cmd->action = SHELL_ACTION_UNKNOWN;
				    shell_cmd->type = SHELL_TYPE_UNKNOWN;
			    }
                            // END: re-init values after shell instance close
		    }

                    //log->error(0xFF, __FILE__, __func__, __LINE__, "type %d[%x-%d][%x-%d],pty master=%d,name=%s\n", j, req_cmd->type, req_cmd->instance, shell_cmd->type, shell_cmd->instance, shell_cmd->pty_master, shell_cmd->pty_name);
		    switch(req_cmd->action) {
                    case SHELL_ACTION_CREATE:
                        if(shell_instance->is_used) {
                            if((shell_cmd->type == req_cmd->type)
                            &&(shell_cmd->instance == req_cmd->instance)) {
                                found_instance = 1;
                            }
                        } else {
                            shell_instance->is_used = 1;
                            log->info(0xFF, __FILE__, __func__, __LINE__, "=CREATE==========\n");
                            memcpy(&shell_cmd->cmd[0], &req_cmd->cmd[0], req_cmd->cmdlen);
                            shell_cmd->cmdlen = req_cmd->cmdlen;
                            int ptr_count = parse(&shell_cmd->cmd[0], shell_cmd->cmdlen, ptr);
                            if(ptr_count > MAX_PTR) {
                                log->error(0xFF, __FILE__, __func__, __LINE__, "ptr count - %d>%d\n", ptr_count, MAX_PTR);
                            }
                            struct winsize ws;
                            pid_t pid = forkpty(&shell_instance->pty_master, &shell_instance->pty_name[0], NULL, &ws);
                            switch(pid) {
                            case -1: // Error
                            break;
                            case 0: // Child
                                chdir("/");
                                int ret = execve(ptr[0], ptr, NULL);
                                if(ret < 0) {
                                }
                                exit(1);
                            break;
                            default: // Parent
                                //shell_instance->is_used = 1;
                                shell_cmd->action = SHELL_ACTION_EXECUTE;
				shell_cmd->type = req_cmd->type;
				shell_cmd->instance = req_cmd->instance;
                                shell_instance->pid = pid;
                                found_instance = 1;
                            break;
                            }
                        }
                    break; 
                    case SHELL_ACTION_EXECUTE:
                        if((shell_instance->is_used)
                        &&(shell_cmd->type == req_cmd->type)
                        &&(shell_cmd->instance == req_cmd->instance)) {
                            log->info(0xFF, __FILE__, __func__, __LINE__, "execute %d- %s\n", req_cmd->cmdlen, req_cmd->cmd);
                            write(shell_instance->pty_master, &req_cmd->cmd[0], req_cmd->cmdlen);
                            write(shell_instance->pty_master, "\n", strlen("\n"));
                            found_instance = 1;
                        } else {
                        }
                    break;
                    case SHELL_ACTION_TERMINATE:
                        if((shell_instance->is_used)
                        &&(shell_cmd->type == req_cmd->type)
                        &&(shell_cmd->instance == req_cmd->instance)) {
                            log->info(0xFF, __FILE__, __func__, __LINE__, "execute %d- %s\n", req_cmd->cmdlen, req_cmd->cmd);
                            shell_cmd->action = SHELL_ACTION_TERMINATE;
                            if(req_cmd->cmdlen > 0) {
                                write(shell_instance->pty_master, &req_cmd->cmd[0], req_cmd->cmdlen);
                                write(shell_instance->pty_master, "\n", strlen("\n"));
                            }
                            found_instance = 1;
                            log->info(0xFF, __FILE__, __func__, __LINE__, "=TERMINATE==========\n");
                        } else {
                        }
                    break;
		    }

                    if(found_instance) {
                        res_cmd->action= shell_cmd->action;
			res_cmd->type = shell_cmd->type;
			res_cmd->type = shell_cmd->instance;
                        found_instance = 0;
                        break; // break out loop of SHELL INSTANCE 
                    } else {
                        log->error(0xFF, __FILE__, __func__, __LINE__, "%d)[%d-%d-%d]\n", j, shell_cmd->action, shell_instance->is_used, shell_instance->pty_master);
                    }
                }
                //res.status = CMD_STATUS_NORMAL;
                res.fn=req.fn;
                res.cmd = req.cmd;
                res.data_size = sizeof(struct shell_cmd_t);
                net->uds_server_send(socket_fd, &res, &uds->cli_addr, uds->cli_addr_len);
                uds->is_used = 0;
		break; // break out loop of CLIENT_SHELL
            }
        }
    }

    return 0;
}

