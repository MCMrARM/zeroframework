#include <zerof/ptrace_mem_so_patcher.h>

#include <unistd.h>
#include <android/log.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sched.h>
#include <dlfcn.h>

#define TAG "PtraceSoPatcher"

using namespace zerof;

bool ptrace_mem_so_patcher::wait_for_syscall(patch_context *parg, pid_t pid) {
    int status;
    if (parg->finished)
        return false;
    while (waitpid(pid, &status, 0) >= 0 && !WIFEXITED(status)) {
        if (parg->finished)
            return false;
        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
            return true;
        ptrace(PTRACE_SYSCALL, pid, NULL, WSTOPSIG(status));
    }
    return false;
}

int ptrace_mem_so_patcher::handle_ptrace(void *arg) {
    patch_context* parg = (patch_context*) arg;

    pid_t pid = parg->pid;
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "ptrace() pid: %i", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "ptrace(PTRACE_ATTACH, ...) failed");
        return 1;
    }
    if (waitpid(pid, NULL, 0) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "waitpid() failed");
        return 1;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "ptrace(PTRACE_SETOPTIONS, ...) failed");
        return 1;
    }

    // Inform the thread we're ready to go
    ptrace(PTRACE_SYSCALL, pid, NULL, SIGUSR1);

    int library_fd = -1;

    while (wait_for_syscall(parg, pid)) {
        struct user regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        unsigned long syscall = regs.regs.uregs[7];
        // __android_log_print(ANDROID_LOG_DEBUG, TAG, "syscall: %lx", syscall);
        if (syscall == 0xC0) {
            size_t addr = (size_t) regs.regs.uregs[0];
            size_t len = (size_t) regs.regs.uregs[1];
            int prot = (int) regs.regs.uregs[2];
            int flags = (int) regs.regs.uregs[3];
            int fd = (int) regs.regs.uregs[4];
            off_t pgoffset = (off_t) regs.regs.uregs[5];

            size_t offset = (size_t) (pgoffset * 4096);

            bool has_matching_patch = false;
            if (fd == library_fd) {
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "mmap2(0x%x, 0x%x, %i, %i, %i, %lu)",
                                    addr, len, prot, flags, fd, pgoffset);
                for (auto const& p : parg->patches) {
                    size_t pend = p.start + p.data.size();
                    if (pend > offset && p.start < offset + len) {
                        has_matching_patch = true;
                        break;
                    }
                }
                if (has_matching_patch && !(prot & PROT_WRITE)) {
                    prot |= PROT_WRITE;
                    regs.regs.uregs[2] = (unsigned long) prot;
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                }
            }


            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            if (!wait_for_syscall(parg, pid))
                break;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            void* ret = (void*) regs.regs.uregs[0];

            if (has_matching_patch && ret != nullptr) {
                for (auto const& p : parg->patches) {
                    size_t pend = p.start + p.data.size();
                    if (pend > offset && p.start < offset + len) {
                        ssize_t poff = (ssize_t) p.start - offset;
                        size_t ploff = 0;
                        if (poff < 0) {
                            ploff = (size_t) (-poff);
                            poff = 0;
                        }
                        memcpy(((char*) ret) + poff, p.data.data() + ploff,
                               std::min(p.data.size() - ploff, len - poff));
                    }
                }
            }
        } else if (syscall == 0x142) {
            size_t filename = (size_t) regs.regs.uregs[1];

            ptrace(PTRACE_SYSCALL, pid, NULL, 0);
            if (!wait_for_syscall(parg, pid))
                break;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            int ret = (int) regs.regs.uregs[0];

            if (strcmp((char*) filename, parg->patch_lib_name.c_str()) == 0) {
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "openat(%s) = %i",
                                    (char*) filename, ret);
                library_fd = ret;
            }
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "ptrace() detaching");

    ptrace(PTRACE_DETACH, pid, NULL, 0);
    kill(pid, SIGUSR1);

    return 0;
}

void* ptrace_mem_so_patcher::load_library(std::string path, std::vector<so_patch> patches) {
    patch_context* patch_info = new patch_context;
    patch_info->pid = getpid();
    patch_info->finished = false;

    patch_info->patch_lib_name = std::move(path);
    patch_info->patches = std::move(patches);
    for (so_patch const& p : patch_info->patches) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Patch: %x-%x",
                            p.start, p.start + p.data.size());
    }

    __android_log_print(ANDROID_LOG_DEBUG, TAG, "My PID: %i", patch_info->pid);

    sigset_t waitset;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGUSR1);
    sigprocmask(SIG_BLOCK, &waitset, NULL);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);

    const size_t stack_size = 1024 * 1024;
    void* stack = malloc(stack_size);
    int child_pid = clone(handle_ptrace, (char*) stack + stack_size,
                          CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_FS, (void*) patch_info);
    if (child_pid < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "clone() failed");
        delete patch_info;
        return nullptr;
    }

    int sig;
    // Wait for the ptrace() to settle in
    if (sigwait(&waitset, &sig) < 0 || sig != SIGUSR1)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sigwait() failed");

    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Loading library");

    void* library_handle = dlopen(patch_info->patch_lib_name.c_str(), RTLD_LAZY);

    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Library loaded");
    patch_info->finished = true;
    // this will interrupt the monitor, and also suspend our thread until the ptrace one is done
    // processing it
    tgkill(getpid(), gettid(), SIGUSR1);
    __android_log_print(ANDROID_LOG_VERBOSE, TAG, "Finishing up");

    delete patch_info;

    return library_handle;
}