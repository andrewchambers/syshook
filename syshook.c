/* See LICENSE file for copyright and license details. */
#include "common.h"
#include "janet.h"

char *argv0;
static unsigned long int trace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
static struct process *current_hook_process;
static JanetTable *enter_hooks;
static JanetTable *exit_hooks;
static JanetFiber *hook_fiber;


_Noreturn static void
usage(void)
{
  fprintf(stderr, "usage: %s [-o trace-output-file] [-ft] (command | -0 command argv0) [argument] ...\n", argv0);
  exit(1);
}

static void
run_janet_syscall_hook(JanetTable *hooks)
{
  switch (janet_fiber_status(hook_fiber)) {
    default:
      return;
    case JANET_STATUS_PENDING:
    case JANET_STATUS_NEW:
      ;
  }

  Janet hook = janet_table_get(hooks, janet_wrap_number((double)current_hook_process->scall));

  if (janet_checktype(hook, JANET_NIL))
    return;

  Janet out;
  JanetSignal s = janet_continue(hook_fiber, hook, &out);
  if (s == JANET_SIGNAL_ERROR)
    janet_stacktrace(hook_fiber, out);
}

static Janet j_arg_string(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  int idx = janet_getnumber(argv, 0);

  if (idx > 5 || idx < 0)
    janet_panicf("arg index must be between 0 and 5");

  if (!current_hook_process->args[idx])
    return janet_wrap_nil();

  size_t len;
  const char *error;

  char *s = get_string(current_hook_process->pid, current_hook_process->args[idx], &len, &error);
  Janet ret = s ? janet_cstringv(s) : janet_wrap_nil();
  free(s);

  if (error)
    janet_panicf("error reading syscall arg[%d] from process(%d): %s", idx, current_hook_process->pid, error);

  return ret;
}

static Janet j_arg_double(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  int idx = janet_getnumber(argv, 0);

  if (idx > 5 || idx < 0)
    janet_panicf("arg index must be between 0 and 5");

  return janet_wrap_number(current_hook_process->args[idx]);
}

static Janet j_arg_i64(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  int idx = janet_getnumber(argv, 0);

  if (idx > 5 || idx < 0)
    janet_panicf("arg index must be between 0 and 5");

  return janet_wrap_s64(current_hook_process->args[idx]);
}

static Janet j_arg_u64(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  int idx = janet_getnumber(argv, 0);

  if (idx > 5 || idx < 0)
    janet_panicf("arg index must be between 0 and 5");

  return janet_wrap_u64(current_hook_process->args[idx]);
}

static const JanetReg jcfuns[] = {
    {"arg-string", j_arg_string, NULL},
    {"arg-double", j_arg_double, NULL},
    {"arg-i64", j_arg_i64, NULL},
    {"arg-u64", j_arg_u64, NULL},
    {NULL, NULL, NULL}
};

static void
hook_systemcall(struct process *proc)
{
  current_hook_process = proc;
  run_janet_syscall_hook(enter_hooks);
}

static void
hook_systemcall_exit(struct process *proc)
{
  current_hook_process = proc;
  run_janet_syscall_hook(exit_hooks);
}

static void
handle_syscall(struct process *proc)
{
  struct user_regs_struct regs;

  switch ((int)proc->state) {
  default:
    /* Get system call arguments */
    if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &regs))
      eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
    proc->scall = regs.SYSCALL_NUM_REG;
#ifdef CHECK_ARCHITECTURE
    CHECK_ARCHITECTURE(proc, &regs);
    proc->scall ^= proc->scall_xor;
#endif
    GET_SYSCALL_ARGUMENTS(proc, &regs);

    hook_systemcall(proc);

    /* Run system call */
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
      eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);

    proc->state = Syscall;
    break;

  case Syscall:
  case CloneParent:
  case ForkParent:
    /* Get system call result */
    if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &regs))
      eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);

    /* Get or set return */
    if (proc->state == Syscall) {
      proc->ret = regs.SYSCALL_RET_REG;
    } else {
      regs.SYSCALL_RET_REG = proc->ret;
      if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &regs))
        eprintf("ptrace PTRACE_SETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
      if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
        eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
    }

    hook_systemcall_exit(proc);

    proc->silent_until_execed -= (proc->silent_until_execed == 1);

    /* Make process continue and stop at next syscall */
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
      eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);

    proc->state = Normal;
    break;

  case Exec:
    proc->silent_until_execed -= (proc->silent_until_execed == 2);
    FALL_THROUGH
    /* fall through */
  case VforkParent:
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
      eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
    proc->state = Syscall;
    break;

  case CloneChild:
  case ForkChild:
  case VforkChild:
    proc->state = Normal;
    break;
  }
}


static void
handle_event(struct process *proc, int status)
{
  int trace_event, sig;
  unsigned long int event;
  struct process *proc2;

  sig = WSTOPSIG(status);
  trace_event = status >> 16;
  switch (trace_event) {

  case PTRACE_EVENT_VFORK:
    FALL_THROUGH
    /* fall through */
  case PTRACE_EVENT_FORK:
  case PTRACE_EVENT_CLONE:
    if (ptrace(PTRACE_GETEVENTMSG, proc->pid, NULL, &event))
      eprintf("ptrace PTRACE_GETEVENTMSG %ju NULL <buffer>:", (uintmax_t)proc->pid);
    proc2 = add_process((pid_t)event, trace_options);
    if (trace_event == PTRACE_EVENT_CLONE)
      proc2->thread_leader = proc->pid;
    proc->ret = event;
    if (trace_event == PTRACE_EVENT_VFORK) {
      proc2->continue_on_exit = proc;
      proc->vfork_waiting_on = proc2;
      proc->state = VforkParent;
    } else {
      proc->state = trace_event == PTRACE_EVENT_CLONE ? CloneParent : ForkParent;
      handle_syscall(proc);
    }
    proc2->state = trace_event == PTRACE_EVENT_FORK ? ForkChild :
      trace_event == PTRACE_EVENT_VFORK ? VforkChild : CloneChild;
    handle_syscall(proc2);
    break;

  case PTRACE_EVENT_EXEC:
    proc->state = Exec;
    handle_syscall(proc);
    proc2 = proc->continue_on_exit;
    if (proc2) {
      proc->continue_on_exit = NULL;
      proc2->vfork_waiting_on = NULL;
      handle_syscall(proc2);
    }
    break;

  case PTRACE_EVENT_STOP:
    switch (sig) {
    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
    stop_signal:
      if (ptrace(PTRACE_LISTEN, proc->pid, NULL, 0))
        eprintf("ptrace PTRACE_LISTEN %ju NULL 0:", (uintmax_t)proc->pid);
      break;
    default:
      if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
        eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
      break;
    }
    break;

  default:
    abort();

  case 0:
    if (ptrace(PTRACE_GETSIGINFO, proc->pid, 0, &(siginfo_t){0}))
      goto stop_signal;
    if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, sig))
      eprintf("ptrace PTRACE_SYSCALL %ju NULL %i:", (uintmax_t)proc->pid, sig);
    break;
  }
}

const char * init_script = 
"(defn syshook-loop [&]\n"
"  ((yield))"
"  (syshook-loop))\n"
"(defn sys-enter* [sc fn]\n"
"  (put *enter-syshooks* sc fn))\n"
"(defmacro sys-enter [sc & body]\n"
"  ~(,sys-enter* ,sc (fn [] ,;body)))\n"
"(defn sys-exit* [sc fn]\n"
"  (put *exit-syshooks* sc fn))\n"
"(defmacro sys-exit [sc & body]\n"
"  ~(,sys-exit* ,sc (fn [] ,;body)))\n"
"(do (def f (fiber/new syshook-loop :yi)) (resume f) f)\n";

int
main(int argc, char **argv)
{
  pid_t pid, orig_pid;
  int status, exit_code = 0, with_argv0 = 0, i, gchandle;
  struct process *proc, *proc2;
  struct sigaction sa;
  sigset_t sm;

  janet_init();

  JanetTable *env = janet_core_env(NULL);

  gchandle = janet_gclock();
  
  enter_hooks = janet_table(1024);
  exit_hooks = janet_table(1024);

  janet_def(env, "*enter-syshooks*", janet_wrap_table(enter_hooks), NULL);
  janet_def(env, "*exit-syshooks*",  janet_wrap_table(exit_hooks), NULL);
  janet_cfuns(env, "syshook", jcfuns);
  Janet scratchj = janet_wrap_nil();
  janet_dostring(env, init_script, "<syshook-init>", &scratchj);
  if (!janet_checktype(scratchj, JANET_FIBER))
    abort();
  janet_def(env, "*syshook-fiber*", scratchj, NULL);
  hook_fiber = janet_unwrap_fiber(scratchj);

  janet_gcroot(janet_wrap_table(enter_hooks));
  janet_gcroot(janet_wrap_table(exit_hooks));
  janet_gcroot(janet_wrap_fiber(hook_fiber));

  janet_gcunlock(gchandle);


  ARGBEGIN {
  case '0':
    with_argv0 = 1;
    break;
  case 'f':
    trace_options |= PTRACE_O_TRACEFORK;
    trace_options |= PTRACE_O_TRACEVFORK;
    FALL_THROUGH
    /* fall through */
  case 't':
    trace_options |= PTRACE_O_TRACECLONE;
    break;
  case 'e':
    janet_dostring(env, EARGF(usage()), "<eval>", &scratchj);
    break;
  default:
    usage();
  } ARGEND;
  if (!argc)
    usage();


  orig_pid = fork();
  switch (orig_pid) {
  case -1:
    eprintf("fork:");
  case 0:
    if (raise(SIGSTOP))
      eprintf_and_kill(getppid(), "raise SIGSTOP:");
    execvp(*argv, &argv[with_argv0]);
    eprintf_and_kill(getppid(), "execvp %s:", *argv);
  default:
    break;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  for (i = 1; i <= _NSIG; i++)
    sigaction(i, &sa, NULL);
  sigemptyset(&sm);
  if (sigprocmask(SIG_SETMASK, &sm, NULL))
    eprintf_and_kill(orig_pid, "sigprocmask SIG_SETMASK <empty sigset_t> NULL:");
  init_process_list();
  add_process(orig_pid, trace_options)->silent_until_execed = 2;

  for (;;) {
    pid = waitpid(-1, &status, __WALL | WCONTINUED);
    if (pid < 0) {
      if (errno == ECHILD)
        break;
      if (errno == EINTR)
        continue;
      eprintf("waitpid -1 <buffer> __WALL|WCONTINUED:");
    }

    proc = find_process(pid);
    if (!proc)
      continue;

    if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == (SIGTRAP | 0x80))
        handle_syscall(proc);
      else
        handle_event(proc, status);
    } else if (WIFCONTINUED(status)) {
      /* TODO Run hook...
      tprintf(proc, "\nProcess continued, presumably by signal %i (SIGCONT: %s)\n", SIGCONT, strsignal(SIGCONT));
      */
    } else {
      if (pid == orig_pid)
        exit_code = status;
      if (WIFEXITED(status)) {
        /* TODO Run hook...
        tprintf(proc, "\nProcess exited with value %i%s\n", WEXITSTATUS(status),
          WCOREDUMP(status) ? ", core dumped" : "");
        */  
      } else {
        /* TODO Run hook...
        tprintf(proc, "\nProcess terminated by signal %i (%s: %s)%s\n", WTERMSIG(status),
          get_signum_name(WTERMSIG(status)), strsignal(WTERMSIG(status)),
          WCOREDUMP(status) ? ", core dumped" : "");
        */
      }
      proc2 = proc->continue_on_exit;
      remove_process(proc);
      if (proc2) {
        /* TODO Run hook...
        if (WIFEXITED(status))
          tprintf(proc2, "\nProcess continues due to exit of vfork child\n");
        else
          tprintf(proc2, "\nProcess continues due to abnormal termination of vfork child\n");
        */
        handle_syscall(proc2);
      }
    }
  }

  janet_deinit();

  if (WIFSIGNALED(exit_code)) {
    exit_code = WTERMSIG(exit_code);
    raise(exit_code);
    return exit_code + 128;
  }
  return WEXITSTATUS(exit_code);
}
