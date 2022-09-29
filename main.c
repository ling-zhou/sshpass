/*  This file is part of "sshpass", a tool for batch running password ssh authentication
 *  Copyright (C) 2006, 2015 Lingnu Open Source Consulting Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version, provided that it was accepted by
 *  Lingnu Open Source Consulting Ltd. as an acceptable license for its
 *  projects. Consult http://www.lingnu.com/licenses.html
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if 1 // HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <pty.h>

enum program_return_codes {
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
};

struct {
    enum { PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS } pwtype;
    union {
        const char* filename;
        const char* password;
        int fd;
    } pwsrc;

    const char* pwprompt;
    int verbose;
} args;

/* use global variables so that this information can be shared with the signal handler */
static int masterpt;

static void show_help() {
    printf("Usage: " PACKAGE_NAME " [-f|-d|-p|-e] [-hV] command parameters\n"
        "   -f filename   Take password to use from file\n"
        "   -d number     Use number as file descriptor for getting password\n"
        "   -p password   Provide password as argument (security unwise)\n"
        "   -e            Password is passed as env-var \"SSHPASS\"\n"
        "   With no parameters - password will be taken from stdin\n\n"
            "   -P prompt     Which string should sshpass search for to detect a password prompt\n"
            "   -v            Be verbose about what you're doing\n"
        "   -h            Show help (this screen)\n"
        "   -V            Print version information\n"
        "At most one of -f, -d, -p or -e should be used\n");
}

// Parse the command line. Fill in the "args" global struct with the results. Return argv offset
// on success, and a negative number on failure
static int parse_options(int argc, char* argv[]) {
    int error = -1;
    int opt;

    // Set the default password source to stdin
    args.pwtype = PWT_STDIN;
    args.pwsrc.fd = 0;

#define VIRGIN_PWTYPE if (args.pwtype != PWT_STDIN) { \
    fprintf(stdout, "Conflicting password source\n"); \
    error = RETURN_CONFLICTING_ARGUMENTS; }

    while ((opt = getopt(argc, argv, "+f:d:p:P:heVv")) != -1 && error == -1) {
        switch(opt) {
        case 'f':
            // Password should come from a file
            VIRGIN_PWTYPE;

            args.pwtype = PWT_FILE;
            args.pwsrc.filename = optarg;
            break;
        case 'd':
            // Password should come from an open file descriptor
            VIRGIN_PWTYPE;

            args.pwtype = PWT_FD;
            args.pwsrc.fd = atoi(optarg);
            break;
        case 'p':
            // Password is given on the command line
            VIRGIN_PWTYPE;

            args.pwtype = PWT_PASS;
            args.pwsrc.password = strdup(optarg);

            // Hide the original password from the command line
            {
                for (int i = 0; optarg[i] != '\0'; ++i)
                    optarg[i] = 'z';
            }
            break;
        case 'P':
            args.pwprompt = optarg;
            break;
        case 'v':
            args.verbose++;
            break;
        case 'e':
            VIRGIN_PWTYPE;

            args.pwtype = PWT_PASS;
            args.pwsrc.password = getenv("SSHPASS");
            if (args.pwsrc.password == NULL) {
                fprintf(stdout,
                        "sshpass: -e option given but SSHPASS environment variable not set\n");
                error = RETURN_INVALID_ARGUMENTS;
            }
            break;
        case '?':
        case ':':
            error = RETURN_INVALID_ARGUMENTS;
            break;
        case 'h':
            error = RETURN_NOERROR;
            break;
        case 'V':
            printf("%s\n"
                   "(C) 2006-2011 Lingnu Open Source Consulting Ltd.\n"
                   "(C) 2015-2016 Shachar Shemesh\n"
                   "This program is free software, and can be distributed under the terms of the GPL\n"
                   "See the COPYING file for more information.\n"
                   "\n"
                   "Using \"%s\" as the default password prompt indicator.\n",
                   PACKAGE_STRING, PASSWORD_PROMPT);
            exit(0);
            break;
        }
    }

    if (error >= 0)
        return -(error + 1);
    else
        return optind;
}

void window_resize_handler(int signum) {
    struct winsize ttysize; // The size of our tty

    printf("in window_resize_handler\n");
    if (ioctl(0, TIOCGWINSZ, &ttysize) == 0)
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    else
        printf("in window_resize_handler\n");
}

// Do nothing handler - makes sure the ppoll will terminate if the signal arrives, though.
void sigchld_handler(int signum) {}

int match(const char* target, const char* buffer, ssize_t bufsize, int pos) {
    // This is a highly simplified implementation.
    // It's good enough for matching "Password: ", though.
    for (int i = 0; target[pos] != '\0' && i < bufsize; ++i) {
        if (target[pos] == buffer[i])
            pos++;
        else {
            pos = 0;
            if (target[pos] == buffer[i])
                pos++;
        }
    }

    return pos;
}

void write_pass_fd(int srcfd, int dstfd) {
    int done = 0;

    while (!done) {
        char buffer[40];
        int numread = read(srcfd, buffer, sizeof(buffer));
        done = (numread < 1);

        for (int i = 0; i < numread && !done; ++i) {
            if (buffer[i] != '\n')
                write(dstfd, buffer + i, 1);
            else
                done = 1;
        }
    }

    write(dstfd, "\n", 1);
}

void write_pass(int fd) {
    switch(args.pwtype) {
    case PWT_STDIN:
        write_pass_fd(STDIN_FILENO, fd);
        break;
    case PWT_FD:
        write_pass_fd(args.pwsrc.fd, fd);
        break;
    case PWT_FILE:
        {
            int srcfd = open(args.pwsrc.filename, O_RDONLY);
            if (srcfd != -1) {
                write_pass_fd(srcfd, fd);
                close(srcfd);
            }
        }
        break;
    case PWT_PASS:
        write(fd, args.pwsrc.password, strlen(args.pwsrc.password));
        write(fd, "\n", 1);
        break;
    }
}

int handleoutput(int fd) {
    static uint64_t rcv_bytes = 0;
    // We are looking for the string
    static int password_sent = 0; // If the "password" prompt repeated, we have the wrong password.
    static int target1_pos = 0, target2_pos = 0;
    static int firsttime = 1;
    static const char* target1 = PASSWORD_PROMPT; // Asking for a password

    // The authenticity of host '[9.*.*.113]:36000 ([9.*.*.113]:36000)' can't be established.
    // ED25519 key fingerprint is SHA256:2pdOL0e****************UcNGtQVv/JRdZA4tL8vw.
    // This key is not known by any other names
    // Are you sure you want to continue connecting (yes/no/[fingerprint])?
    // solution:
    //   ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no
    static const char* target2 = "The authenticity of host "; // Asks to authenticate host

    // static const char target3[] = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!";
    // Warns about man in the middle attack, The remote identification changed error is sent to
    // stdout, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    char buffer[256];
    int ret = 0;

    args.verbose = 1;

    if (args.pwprompt) {
        target1 = args.pwprompt;
    }

    if (args.verbose && firsttime) {
        firsttime = 0;
        fprintf(stdout, "SSHPASS searching for password prompt using match \"%s\"\n", target1);
        fflush(stdout);
    }

    int numread = read(fd, buffer, sizeof(buffer) - 1);
    if (numread == 0) {
        fprintf(stdout, "got EOF, exiting ...\n");
        fflush(stdout);
        exit(0);
    } else if (numread < 0) {
        fprintf(stdout, "got err: %s\n", strerror(errno));
        fflush(stdout);
        exit(1);
    }

    buffer[numread] = '\0';
    rcv_bytes += numread;
    printf("<<<(%d): %s>>>\n", numread, buffer);
    fflush(stdout);

    if (args.verbose) {
        fprintf(stdout, "SSHPASS read: %s\n", buffer);
        fflush(stdout);
    }

    // FIXME, XXX
    target1_pos = match(target1, buffer, numread, target1_pos);

    // Are we at a password prompt?
    if (target1[target1_pos] == '\0') {
        // 此时不存在 The authenticity of host
        // 因为 The authenticity of host 比 password 先出现
        if (!password_sent) {
            if (args.verbose) {
                fprintf(stdout, "SSHPASS detected prompt. Sending password.\n");
                fflush(stdout);
            }
            write_pass(fd);
            target1_pos = 0;
            password_sent = 1;
        } else {
            // Wrong password - terminate with proper error code
            if (args.verbose) {
                fprintf(stdout, "SSHPASS detected prompt, again. Wrong password. Terminating.\n");
                fflush(stdout);
            }
            ret = RETURN_INCORRECT_PASSWORD;
        }
    }

    if (ret == 0) {
        // XXX
        target2_pos = match(target2, buffer, numread, target2_pos);

        // Are we being prompted to authenticate the host?
        if (target2[target2_pos] == '\0') {
            if (args.verbose) {
                fprintf(stdout, "SSHPASS detected host authentication prompt. Exiting.\n");
                fflush(stdout);
            }
            ret = RETURN_HOST_KEY_UNKNOWN;
        }
    }

    return ret;
}

int runprogram(int argc, char* argv[]) {
    struct winsize ttysize; // The size of our tty

    // We need to interrupt a ppoll with a SIGCHLD. In order to do so, we need a SIGCHLD handler
    signal(SIGCHLD, sigchld_handler);

    char slave_dev_name[128];
    int slavept;

    int rc = openpty(&masterpt, &slavept, slave_dev_name, NULL, NULL);
    if (rc < 0) {
        perror("openpty");
        return RETURN_RUNTIME_ERROR;
    }

    // Calling posix_openpt() creates a pathname for the corresponding pseudoterminal slave device.
    // The pathname of the __slave device__ can be obtained using ptsname(3).
    // The slave device pathname exists only as long as the master device is open.
    //
    // Create a pseudo terminal for our process
    //   An unused UNIX 98 pseudoterminal master is opened by calling posix_openpt(3).

    // If a process has a __controlling terminal__, opening the special file __/dev/tty__ obtains a
    // file  descriptor  for  that  terminal.  This  is  useful  if  standard  input  and
    // output  are redirected, and a program wants to ensure that it is communicating with
    // the controlling terminal. For example, the getpass() function described in Section
    // 8.5 opens /dev/tty for this purpose. If the process doesn’t have a controlling terminal,
    // opening /dev/tty fails with the error ENXIO.

    // As long as processes exist that have the slave end as their controlling TTYs,
    // __new slave fds__ can be created by __opening /dev/tty__,
    // which is exactly what __ssh is doing__.

    if (ioctl(0, TIOCGWINSZ, &ttysize) == 0) {
        printf("register SIGWINCH signal\n");
        signal(SIGWINCH, window_resize_handler);
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    }

    /*
       This comment documents the history of code.

       We need to open the slavept inside the child process, after "setsid",
       so that it becomes the __controlling TTY__ for the process.
       We do not, otherwise, need the file descriptor open. The original approach was to
       close the fd immediately after, as it is no longer needed.

       It turns out that the Linux kernel considers a master ptty fd that has
       no open slave fds to be unused, and causes "ppoll" to return with "error on fd".
       The subsequent read would fail, causing us to go into an infinite loop.
       This is a bug in the kernel, as the fact that a master ptty fd has no slaves
       is not a permanent problem.

       ** As long as processes exist that have the slave end as their controlling TTYs, new **
       ** slave fds can be created by opening /dev/tty, which is exactly what ssh is doing **.

       Our attempt at solving this problem was to have the child process not close
       its end of the slave ptty fd. We do leak this fd, but this was a small
       price to pay. This worked great up until openssh version 5.6.

       Openssh version 5.6 looks at all of its open file descriptors, and closes any that
       it does not know what they are for. While entirely within its prerogative,
       this breaks our fix, causing sshpass to either hang, or do the infinite loop again.

       Our solution is to keep the slave end open in both parent AND child, at least until the
       handshake is complete, at which point we no longer need to monitor the TTY anyways.
     */

    int childpid = fork();
    if (childpid == 0) { // Child
        // Call setsid(), to create a new session (Section 34.3).
        // The child is the leader of the new session and loses its
        // controlling terminal (if it had one).
        setsid(); // Detach us from the current TTY

        // Open the pseudoterminal slave. Since the child lost its controlling terminal
        // in the previous step, this step causes the pseudoterminal slave to become
        // the controlling terminal for the child.
        // This line makes the ptty our controlling tty. We do not otherwise need it open
        printf("child: open slave_dev_name(%s)\n", slave_dev_name);
        fflush(stdout);
        slavept = open(slave_dev_name, O_RDWR);
        close(slavept); // XXX?

        // Close the file descriptor for the pseudoterminal master,
        // since it is not required in the child.
        close(masterpt);

        execvp(argv[0], argv);
        perror("system BUG: sshpass: Failed to run command");
        exit(RETURN_RUNTIME_ERROR);
    } else if (childpid < 0) {
        perror("sshpass: Failed to create child process");
        return RETURN_RUNTIME_ERROR;
    }

    // We are the parent
    printf("parent: open slave_dev_name(%s)\n", slave_dev_name);
    fflush(stdout);
    slavept = open(slave_dev_name, O_RDWR|O_NOCTTY);

    int status = 0;
    int terminate = 0;
    pid_t wait_id;
    sigset_t sigmask, sigmask_ppoll;
    struct pollfd pfd = {masterpt, POLLIN, 0};

    // Set the signal mask during the ppoll
    sigemptyset(&sigmask_ppoll);

    // And during the regular run
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    sigprocmask(SIG_SETMASK, &sigmask, NULL);

    do {
        if (!terminate) {
            int ret = ppoll(&pfd, 1, NULL, &sigmask_ppoll);

            if (ret > 0) {
                int ret = handleoutput(masterpt);
                if (ret != 0) { // FIXME, no < 0
                    // Authentication failed or any other error

                    // handleoutput returns positive error number in case of some error, and
                    // a negative value if all that happened is that the slave end of the pt
                    // is closed.
                    if (ret > 0) {
                        close(masterpt); // Signal ssh that it's controlling TTY is now closed
                        close(slavept);
                    }

                    terminate = ret;
                    if (terminate) {
                        close(slavept);
                    }
                }
            }

            wait_id = waitpid(childpid, &status, WNOHANG);
        } else {
            wait_id = waitpid(childpid, &status, 0);
        }
    } while (wait_id == 0 || (!WIFEXITED(status) && !WIFSIGNALED(status)));

    if (terminate > 0)
        return terminate;
    else if (WIFEXITED(status))
        return WEXITSTATUS(status);
    else
        return 255;
}

int main(int argc, char* argv[]) {
    int opt_offset = parse_options(argc, argv);

    if (opt_offset < 0) {
        // There was some error
        show_help();
        return -(opt_offset + 1); // -1 becomes 0, -2 becomes 1 etc.
    }

    if (argc - opt_offset < 1) {
        show_help();
        return 0;
    }

    return runprogram(argc - opt_offset, argv + opt_offset);
}
