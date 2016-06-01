/*
 * fslogger-yaml.c
 *
 * WARNING: Proof of Concept, only. Not tested for security or efficiency. 
 *
 * A version of fslogger that outputs file information in YAML format. This
 * code is a modification of Eric Walkingshaw's fslogger which is a patched
 * version of Amit Singh's fslogger utility.
 *
 * Author: Don C. Weber (@cutaway)
 * Start Date: 20160518
 *
 * Compiled and tested on Mac OS X 10.11.4
 *
 * > git clone https://github.com/cutaway/fslogger-yaml.git
 * > cd fslogger-yaml
 * > git clone https://github.com/opensource-apple/xnu.git xnu
 * > gcc -I./xnu/bsd -Wall -o fslogger-yaml udp_client.c fslogger-yaml.c
 *
 * Testing UDP functionality use default settings and set up NetCat listener
 *
 * > nc -ul 127.0.0.1 12345 >test_output_udp.yaml
 *
 * Original file header:
 *
 * Copyright (c) 2008 Amit Singh (osxbook.com).
 * http://osxbook.com/software/fslogger/
 *
 * Source released under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.0.
 * See http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt for details.
 *
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/fsevents.h>
#include <pwd.h>
#include <grp.h>
#include "udp_client.h"

#define PROGNAME "fslogger-yaml"
#define PROGVERS "2.1-yaml"

#define DEV_FSEVENTS     "/dev/fsevents" // the fsevents pseudo-device
#define FSEVENT_BUFSIZ   131072          // buffer for reading from the device
#define EVENT_QUEUE_SIZE 4096            // limited by MAX_KFS_EVENTS
#define MAX_FILENAME     256              // Max file name size

// an event argument
typedef struct kfs_event_arg {
    u_int16_t  type;         // argument type
    u_int16_t  len;          // size of argument data that follows this field
    union {
        struct vnode *vp;
        char         *str;
        void         *ptr;
        int32_t       int32;
        dev_t         dev;
        ino_t         ino;
        int32_t       mode;
        uid_t         uid;
        gid_t         gid;
        uint64_t      timestamp;
    } data;
} kfs_event_arg_t;

#define KFS_NUM_ARGS  FSE_MAX_ARGS

// an event
typedef struct kfs_event {
    int32_t         type; // event type
    pid_t           pid;  // pid of the process that performed the operation
    kfs_event_arg_t args[KFS_NUM_ARGS]; // event arguments
} kfs_event;

// event names
static const char *kfseNames[] = {
    "FSE_CREATE_FILE",
    "FSE_DELETE",
    "FSE_STAT_CHANGED",
    "FSE_RENAME",
    "FSE_CONTENT_MODIFIED",
    "FSE_EXCHANGE",
    "FSE_FINDER_INFO_CHANGED",
    "FSE_CREATE_DIR",
    "FSE_CHOWN",
    "FSE_XATTR_MODIFIED",
    "FSE_XATTR_REMOVED",
};

// argument names
static const char *kfseArgNames[] = {
    "FSE_ARG_UNKNOWN", "FSE_ARG_VNODE", "FSE_ARG_STRING", "FSE_ARGPATH",
    "FSE_ARG_INT32",   "FSE_ARG_INT64", "FSE_ARG_RAW",    "FSE_ARG_INO",
    "FSE_ARG_UID",     "FSE_ARG_DEV",   "FSE_ARG_MODE",   "FSE_ARG_GID",
    "FSE_ARG_FINFO",
};

// for pretty-printing of vnode types
enum vtype {
    VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

enum vtype iftovt_tab[] = {
    VNON, VFIFO, VCHR, VNON, VDIR,  VNON, VBLK, VNON,
    VREG, VNON,  VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};

static const char *vtypeNames[] = {
    "VNON",  "VREG",  "VDIR", "VBLK", "VCHR", "VLNK",
    "VSOCK", "VFIFO", "VBAD", "VSTR", "VCPLX",
};
#define VTYPE_MAX (sizeof(vtypeNames)/sizeof(char *))

static char *
get_proc_name(pid_t pid)
{
    size_t        len = sizeof(struct kinfo_proc);
    static int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    static struct kinfo_proc kp;

    name[3] = pid;

    kp.kp_proc.p_comm[0] = '\0';
    if (sysctl((int *)name, sizeof(name)/sizeof(*name), &kp, &len, NULL, 0))
        return "?";

    if (kp.kp_proc.p_comm[0] == '\0')
        return "exited?";

    return kp.kp_proc.p_comm;
}

void usage(){
    fprintf(stderr, "%s (%s)\n", PROGNAME, PROGVERS);
    fprintf(stderr, "File system change logger for Mac OS X. Usage:\n");
    fprintf(stderr, "\n\tsudo ./%s [output file]\n\n", PROGNAME);
    fprintf(stderr, "\t\t-h:            Print this help.\n");
    fprintf(stderr, "\t\t-f <filename>: Ooutput to a local file instead of STDOUT.\n");
    fprintf(stderr, "\t\t-u:            Output to UDP instead of STDOUT. Default: 127.0.0.1:12345.\n");
    fprintf(stderr, "\t\t-s <x.x.x.x>:  Remote IP address to send UDP data. Default: 127.0.0.1\n");
    fprintf(stderr, "\t\t-p <#>:        Remote port number to send UDP data. Default: 12345.\n");
    fprintf(stderr, "\n\nThis program must be run as root using sudo.\n");
    fprintf(stderr, "Happy Hunting, Cutaway.\n\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    int32_t arg_id;
    int     fd, clonefd = -1;
    int     i, j, eoff, off, ret;
    FILE*   onf;
    char    msg[MAX_SEND];
    int     c;
    int     mlen          = 0;
    int     udp           = 0;
    int     det           = 0;
    char    fname[MAX_FILENAME] = "";
    char    raddr[MAX_IP] = "127.0.0.1";
    int     rport         = 12345;

    kfs_event_arg_t *kea;
    struct           fsevent_clone_args fca;
    char             buffer[FSEVENT_BUFSIZ];
    struct passwd   *p;
    struct group    *g;
    mode_t           va_mode;
    u_int32_t        va_type;
    u_int32_t        is_fse_arg_vnode = 0;
    char             fileModeString[11 + 1];
    int8_t           event_list[] = { // action to take for each event
                         FSE_REPORT,  // FSE_CREATE_FILE,
                         FSE_REPORT,  // FSE_DELETE,
                         FSE_REPORT,  // FSE_STAT_CHANGED,
                         FSE_REPORT,  // FSE_RENAME,
                         FSE_REPORT,  // FSE_CONTENT_MODIFIED,
                         FSE_REPORT,  // FSE_EXCHANGE,
                         FSE_REPORT,  // FSE_FINDER_INFO_CHANGED,
                         FSE_REPORT,  // FSE_CREATE_DIR,
                         FSE_REPORT,  // FSE_CHOWN,
                         FSE_REPORT,  // FSE_XATTR_MODIFIED,
                         FSE_REPORT,  // FSE_XATTR_REMOVED,
                     };

    // Print usage if not root
    if (geteuid() != 0){
        usage();
        exit(1);
    }

    onf = stdout;
    opterr = 0;
    while ((c = getopt (argc, argv, "huf:s:p:")) != -1)
        switch (c){
            case 'f':
                strncpy(fname,optarg,MAX_FILENAME - 1);
                    
                onf = fopen(fname,"w");
                if (onf == NULL){
                    fprintf(stderr, "Cannot open output file %s.\n\n",optarg);
                    usage();
                    exit(1);
                }
                break;
            case 'u':
                udp = 1;
                break;
            case 's':
                strncpy(raddr,optarg,MAX_IP);
                break;
            case 'p':
                rport = atoi( optarg );
                break;
            case 'h':
            case '?':
                if (optopt == 'f'){
                    fprintf(stderr, "Output filename required.\n");
                    usage();
                    exit(1);
                }
                usage();
                exit(1);
        }

    //setbuf(stdout, NULL);
    setbuf(onf, NULL);

    //Set UDP Socket
    //set_dest("127.0.0.1", 12345);
    set_dest(raddr, rport);
    set_sock();

    if ((fd = open(DEV_FSEVENTS, O_RDONLY)) < 0) {
        perror("open");
        exit(1);
    }

    fca.event_list = (int8_t *)event_list;
    fca.num_events = sizeof(event_list)/sizeof(int8_t);
    fca.event_queue_depth = EVENT_QUEUE_SIZE;
    fca.fd = &clonefd; 
    if ((ret = ioctl(fd, FSEVENTS_CLONE, (char *)&fca)) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }

    close(fd);

    //YAML comments lines start with '#'. Use this for debug and status statements
    snprintf(msg, MAX_DATA,"#fsevents device cloned (fd %d)\n#fslogger ready\n",clonefd);
    // TODO: Make this a function
    if (udp){
        send_packet(msg, strlen(msg));
    } else {
        fprintf(onf,"%s",msg);
        fflush(onf);
    }

    if ((ret = ioctl(clonefd, FSEVENTS_WANT_EXTENDED_INFO, NULL)) < 0) {
        perror("ioctl");
        close(clonefd);
        exit(1);
    }

    while (1) { // event processing loop

        if ((ret = read(clonefd, buffer, FSEVENT_BUFSIZ)) > 0){
            snprintf(msg, MAX_DATA, "# => received %d bytes\n", ret);
            if (udp){
                send_packet(msg, strlen(msg));
            } else {
                fprintf(onf,"%s", msg);
                fflush(onf);
            }
        }

        off = 0;

        while (off < ret) { // process one or more events received
        
            // Start message over
            mlen = 0;
            printf("%s\n",msg);

            struct kfs_event *kfse = (struct kfs_event *)((char *)buffer + off);

            off += sizeof(int32_t) + sizeof(pid_t); // type + pid

            //snprintf(msg, MAX_DATA, "---\n");
            mlen += snprintf(msg + mlen, MAX_DATA, "---\n");
            /*
            if (udp){
                send_packet(msg, strlen(msg));
            } else {
                fprintf(onf,"%s", msg);
                fflush(onf);
            }*/

            if (kfse->type == FSE_EVENTS_DROPPED) { // special event
                //snprintf(msg, MAX_DATA, "Event\n");
                mlen += snprintf(msg + mlen, MAX_DATA, "Event\n");
                //Use snprintf for formatting to permit concantenting the message together
                //snprintf(msg, MAX_DATA, "%s %s = %s\n", msg, "type", "EVENTS DROPPED");
                //snprintf(msg, MAX_DATA, "%s %s = %d\n", msg, "pid", kfse->pid);
                mlen += snprintf(msg + mlen, MAX_DATA, " %s = %s\n", "type", "EVENTS DROPPED");
                mlen += snprintf(msg + mlen, MAX_DATA, " %s = %d\n", "pid", kfse->pid);
                // Special event with continue. So send data
                if (udp){
                    send_packet(msg, strlen(msg));
                } else {
                    fprintf(onf,"%s", msg);
                    fflush(onf);
                }

                off += sizeof(u_int16_t); // FSE_ARG_DONE: sizeof(type)
                continue;
            }

            int32_t atype = kfse->type & FSE_TYPE_MASK;
            uint32_t aflags = FSE_GET_FLAGS(kfse->type);

            if ((atype < FSE_MAX_EVENTS) && (atype >= -1)) {
                //snprintf(msg, MAX_DATA, "Event:\n");
                mlen += snprintf(msg + mlen, MAX_DATA, "Event:\n");
                //snprintf(msg, MAX_DATA, "%s %s: %s", msg, "type", kfseNames[atype]);
                mlen += snprintf(msg + mlen, MAX_DATA, " %s: %s", "type", kfseNames[atype]);
                if (aflags & FSE_COMBINED_EVENTS) {
                    //snprintf(msg, MAX_DATA,"%s%s", msg, ", combined events");
                    mlen += snprintf(msg + mlen, MAX_DATA,"%s", ", combined events");
                }
                if (aflags & FSE_CONTAINS_DROPPED_EVENTS) {
                    //snprintf(msg, MAX_DATA, "%s%s", msg, ", contains dropped events");
                    mlen += snprintf(msg + mlen, MAX_DATA, "%s", ", contains dropped events");
                }
                //snprintf(msg,MAX_DATA,"%s\n",msg);
                mlen += snprintf(msg + mlen,MAX_DATA, "%s","\n");


            } else { // should never happen
                //fprintf(onf, "# This may be a program bug (type = %d).\n", atype);
                mlen += snprintf(msg + mlen, MAX_DATA, "# This may be a program bug (type = %d).\n", atype);
                // Special event with exit. So send data
                if (udp){
                    send_packet(msg, strlen(msg));
                } else {
                    fprintf(onf,"%s", msg);
                    fflush(onf);
                }
                exit(1);
            }

            //snprintf(msg, MAX_DATA, "%s %s: %d\n", msg, "pid", kfse->pid);
            //snprintf(msg, MAX_DATA, "%s %s: %s\n",msg, "pname", get_proc_name(kfse->pid));
            mlen += snprintf(msg + mlen, MAX_DATA, " %s: %d\n", "pid", kfse->pid);
            mlen += snprintf(msg + mlen, MAX_DATA, " %s: %s\n", "pname", get_proc_name(kfse->pid));
            /*if (udp){
                send_packet(msg, strlen(msg));
            } else {
                fprintf(onf,"%s", msg);
                fflush(onf);
            }*/

            //snprintf(msg, MAX_DATA, "Details:\n");
            mlen += snprintf(msg + mlen, MAX_DATA, "%s", "Details:\n");

            kea = kfse->args; 
            i = 0;

            //while ((off < ret) && (i <= FSE_MAX_ARGS)) { // process arguments
            while (off < ret) {

                i++;

                if (kea->type == FSE_ARG_DONE) { // no more arguments
                    //snprintf(msg, MAX_DATA, "%s %s:\n", msg, "FSE_ARG_DONE");
                    mlen += snprintf(msg + mlen, MAX_DATA, " %s:\n", "FSE_ARG_DONE");
                    // Added Length for FSE_ARG_DONE to be consistent with other values
                    //snprintf(msg, MAX_DATA, "%s   %s: %d\n", msg, "len", 0);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d\n", "len", 0);
                    // Added Type for FSE_ARG_DONE to be consistent with other values
                    //snprintf(msg, MAX_DATA, "%s   %s: %d\n", msg, "type", kea->type);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d\n", "type", kea->type);

                    //This should be the only time to send data for a YAML doc which is a full FSEVENT
                    if (udp){
                        send_packet(msg, strlen(msg));
                    } else {
                        fprintf(onf,"%s", msg);
                        fflush(onf);
                    }
                    det = 0;
                    off += sizeof(u_int16_t);
                    break;
                }

                eoff = sizeof(kea->type) + sizeof(kea->len) + kea->len;
                off += eoff;

                arg_id = (kea->type > FSE_MAX_ARGS) ? 0 : kea->type;
                //snprintf(msg, MAX_DATA, "%s %s:\n", msg, kfseArgNames[arg_id]);
                //snprintf(msg, MAX_DATA, "%s   %s: %d\n", msg, "len", kea->len);
                // Do no put detail marker on timestamp
                if (arg_id == 5){
                    mlen += snprintf(msg + mlen, MAX_DATA, " %s:\n", kfseArgNames[arg_id]);
                } else {
                    mlen += snprintf(msg + mlen, MAX_DATA, " %s_%d:\n", kfseArgNames[arg_id],det);
                }
                mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d\n", "len", kea->len);

                switch (kea->type) { // handle based on argument type

                case FSE_ARG_VNODE:  // a vnode (string) pointer
                    is_fse_arg_vnode = 1;
                    //snprintf(msg, MAX_DATA, "%s   %s: %s\n", msg, "path", (char *)&(kea->data.vp));
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %s\n", "path", (char *)&(kea->data.vp));
                    break;

                case FSE_ARG_STRING: // a string pointer
                    // Added double quotes to protect strings with ":"s 
                    //snprintf(msg, MAX_DATA, "%s   %s: \"%s\"\n", msg, "string", (char *)&(kea->data.str)-4);
                    // Actually, to handle "\" it needs to be a single quote
                    //snprintf(msg, MAX_DATA, "%s   %s: \'%s\'\n", msg, "string", (char *)&(kea->data.str)-4);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: \'%s\'\n", "string", (char *)&(kea->data.str)-4);
                    break;

                case FSE_ARG_INT32:
                    //snprintf(msg, MAX_DATA, "%s   %s: %d\n", msg, "int32", kea->data.int32);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d\n", "int32", kea->data.int32);
                    break;

                case FSE_ARG_RAW: // a void pointer
                    //snprintf(msg, MAX_DATA, "%s   %s: ", msg, "ptr");
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: ", "ptr");
                    for (j = 0; j < kea->len; j++)
                        //snprintf(msg, MAX_DATA, "%s%02x ", msg, ((char *)kea->data.ptr)[j]);
                        mlen += snprintf(msg + mlen, MAX_DATA, "%02x ", ((char *)kea->data.ptr)[j]);
                    //snprintf(msg, MAX_DATA, "%s\n", msg);
                    mlen += snprintf(msg + mlen, MAX_DATA, "%s", "\n");
                    break;

                case FSE_ARG_INO: // an inode number
                    //snprintf(msg, MAX_DATA, "%s   %s: %d\n", msg, "ino", (int)kea->data.ino);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d\n", "ino", (int)kea->data.ino);
                    break;

                case FSE_ARG_UID: // a user ID
                    p = getpwuid(kea->data.uid);
                    //snprintf(msg, MAX_DATA, "%s   %s: %d (%s)\n", msg, "uid", kea->data.uid, (p) ? p->pw_name : "?");
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d (%s)\n", "uid", kea->data.uid, (p) ? p->pw_name : "?");
                    break;

                case FSE_ARG_DEV: // a file system ID or a device number
                    if (is_fse_arg_vnode) {
                        //snprintf(msg, MAX_DATA, "%s   %s: %#08x\n", msg, "fsid", kea->data.dev);
                        mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %#08x\n", "fsid", kea->data.dev);
                        is_fse_arg_vnode = 0;
                    } else {
                        //snprintf(msg, MAX_DATA, "%s   %s: %#08x (major %u, minor %u)\n", msg, "dev", kea->data.dev, major(kea->data.dev), minor(kea->data.dev));
                        mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %#08x (major %u, minor %u)\n", "dev", kea->data.dev, major(kea->data.dev), minor(kea->data.dev));
                    }
                    break;

                case FSE_ARG_MODE: // a combination of file mode and file type
                    va_mode = (kea->data.mode & 0x0000ffff);
                    va_type = (kea->data.mode & 0xfffff000);
                    strmode(va_mode, fileModeString);
                    va_type = iftovt_tab[(va_type & S_IFMT) >> 12];
                    //snprintf(msg, MAX_DATA, "%s   %s: %s (%#08x, vnode type %s)", msg, "mode", fileModeString, kea->data.mode, (va_type < VTYPE_MAX) ?  vtypeNames[va_type] : "?");
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %s (%#08x, vnode type %s)", "mode", fileModeString, kea->data.mode, (va_type < VTYPE_MAX) ?  vtypeNames[va_type] : "?");
                    if (kea->data.mode & FSE_MODE_HLINK) {
                        //snprintf(msg, MAX_DATA, "%s%s", msg, ", hard link");
                        mlen += snprintf(msg + mlen, MAX_DATA, "%s", ", hard link");
                    }
                    if (kea->data.mode & FSE_MODE_LAST_HLINK) {
                        //snprintf(msg, MAX_DATA, "%s%s", msg, ", link count zero now");
                        mlen += snprintf(msg + mlen, MAX_DATA, "%s", ", link count zero now");
                    }
                    //snprintf(msg, MAX_DATA, "%s\n", msg);
                    mlen += snprintf(msg + mlen, MAX_DATA, "%s", "\n");
                    break;

                case FSE_ARG_GID: // a group ID
                    g = getgrgid(kea->data.gid);
                    //snprintf(msg, MAX_DATA, "%s   %s: %d (%s)\n", msg, "gid", kea->data.gid, (g) ? g->gr_name : "?");
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %d (%s)\n", "gid", kea->data.gid, (g) ? g->gr_name : "?");
                    // This is usually the last value before everything repeats. Inc det
                    det += 1;
                    break;

                case FSE_ARG_INT64: // timestamp
                    //snprintf(msg, MAX_DATA, "%s   %s: %llu\n", msg, "tstamp", kea->data.timestamp);
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s: %llu\n", "tstamp", kea->data.timestamp);
                    break;

                default:
                    //snprintf(msg, MAX_DATA, "%s   %s = ?\n", msg, "unknown");
                    mlen += snprintf(msg + mlen, MAX_DATA, "   %s = ?\n", "unknown");
                    break;
                }

                kea = (kfs_event_arg_t *)((char *)kea + eoff); // next
            } // for each argument
        } // for each event
    } // forever

    close(clonefd);

    // Only close output file if it is not stdout
    if (argc == 2) {
        fclose(onf);
    }

    exit(0);
}
