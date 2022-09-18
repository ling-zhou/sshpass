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
#include <sys/select.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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
static int ourtty; // Our own tty
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
    fprintf(stderr, "Conflicting password source\n"); \
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
                int i;
                for (i = 0; optarg[i] != '\0'; ++i)
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
                fprintf(stderr,
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

    if (ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0)
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
}

// Do nothing handler - makes sure the select will terminate if the signal arrives, though.
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
        int i;
        int numread = read(srcfd, buffer, sizeof(buffer));
        done = (numread < 1);

        for (i = 0; i < numread && !done; ++i) {
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
    // stderr, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    char buffer[256];
    int ret = 0;

    if (args.pwprompt) {
        target1 = args.pwprompt;
    }

    if (args.verbose && firsttime) {
        firsttime = 0;
        fprintf(stderr, "SSHPASS searching for password prompt using match \"%s\"\n", target1);
    }

    int numread = read(fd, buffer, sizeof(buffer) - 1);
    buffer[numread] = '\0';
    if (args.verbose) {
        fprintf(stderr, "SSHPASS read: %s\n", buffer);
    }

    target1_pos = match(target1, buffer, numread, target1_pos);

    // Are we at a password prompt?
    if (target1[target1_pos] == '\0') {
        if (!password_sent) {
            if (args.verbose)
                fprintf(stderr, "SSHPASS detected prompt. Sending password.\n");
            write_pass(fd);
            target1_pos = 0;
            password_sent = 1;
        } else {
            // Wrong password - terminate with proper error code
            if (args.verbose)
                fprintf(stderr, "SSHPASS detected prompt, again. Wrong password. Terminating.\n");
            ret = RETURN_INCORRECT_PASSWORD;
        }
    }

    if (ret == 0) {
        target2_pos = match(target2, buffer, numread, target2_pos);

        // Are we being prompted to authenticate the host?
        if (target2[target2_pos] == '\0') {
            if (args.verbose)
                fprintf(stderr, "SSHPASS detected host authentication prompt. Exiting.\n");
            ret = RETURN_HOST_KEY_UNKNOWN;
        }
    }

    return ret;
}

int runprogram(int argc, char* argv[]) {
    struct winsize ttysize; // The size of our tty

    // We need to interrupt a select with a SIGCHLD. In order to do so, we need a SIGCHLD handler
    signal(SIGCHLD, sigchld_handler);

    // Calling posix_openpt() creates a pathname for the corresponding pseudoterminal slave device.
    // The pathname of the __slave device__ can be obtained using ptsname(3).
    // The slave device pathname exists only as long as the master device is open.
    //
    // Create a pseudo terminal for our process
    //   An unused UNIX 98 pseudoterminal master is opened by calling posix_openpt(3).
    masterpt = posix_openpt(O_RDWR);
    if (masterpt == -1) {
        perror("Failed to get a pseudo terminal");
        return RETURN_RUNTIME_ERROR;
    }

    fcntl(masterpt, F_SETFL, O_NONBLOCK);

    if (grantpt(masterpt) != 0) {
        perror("Failed to change pseudo terminal's permission");
        return RETURN_RUNTIME_ERROR;
    }

    if (unlockpt(masterpt) != 0) {
        perror("Failed to unlock pseudo terminal");
        return RETURN_RUNTIME_ERROR;
    }

    ourtty = open("/dev/tty", 0); // XXX
    if (ourtty != -1 && ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0) {
        signal(SIGWINCH, window_resize_handler);
        ioctl(masterpt, TIOCSWINSZ, &ttysize);
    }

    // The pathname of the slave device can be obtained using ptsname(3).
    const char* slave_dev_name = ptsname(masterpt);
    int slavept;
    /*
       This comment documents the history of code.

       We need to open the slavept inside the child process, after "setsid",
       so that it becomes the __controlling TTY__ for the process.
       We do not, otherwise, need the file descriptor open. The original approach was to
       close the fd immediately after, as it is no longer needed.

       It turns out that the Linux kernel considers a master ptty fd that has
       no open slave fds to be unused, and causes "select" to return with "error on fd".
       The subsequent read would fail, causing us to go into an infinite loop.
       This is a bug in the kernel, as the fact that a master ptty fd has no slaves
       is not a permanent problem.
       As long as processes exist that have the slave end as their controlling TTYs, new
       slave fds can be created by opening /dev/tty, which is exactly what ssh is doing.

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
        setsid(); // Detach us from the current TTY

        // This line makes the ptty our controlling tty. We do not otherwise need it open
        slavept = open(slave_dev_name, O_RDWR);
        close(slavept);
        close(masterpt);

        execvp(argv[0], argv);
        perror("system BUG: sshpass: Failed to run command");
        exit(RETURN_RUNTIME_ERROR);
    } else if (childpid < 0) {
        perror("sshpass: Failed to create child process");
        return RETURN_RUNTIME_ERROR;
    }

    // We are the parent
    slavept = open(slave_dev_name, O_RDWR|O_NOCTTY);

    int status = 0;
    int terminate = 0;
    pid_t wait_id;
    sigset_t sigmask, sigmask_select;

    // Set the signal mask during the select
    sigemptyset(&sigmask_select);

    // And during the regular run
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    sigprocmask(SIG_SETMASK, &sigmask, NULL);

    do {
        if (!terminate) {
            fd_set readfd;

            FD_ZERO(&readfd);
            FD_SET(masterpt, &readfd);

            int selret = pselect(masterpt + 1, &readfd, NULL, NULL, NULL, &sigmask_select);

            if (selret > 0 && FD_ISSET(masterpt, &readfd)) {
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
