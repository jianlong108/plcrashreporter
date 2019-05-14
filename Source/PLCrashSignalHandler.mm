/*
 * Author: Landon Fuller <landonf@plausiblelabs.com>
 *
 * Copyright (c) 2008-2009 Plausible Labs Cooperative, Inc.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 https://man.openbsd.org/sigaction.2
 系统定义了一组可以传递给进程的信号。信号传递类似于硬件中断的发生:信号通常被阻止，不再发生进一步的中断，保存当前进程上下文，并构建一个新的进程上下文。进程可以指定传递信号的处理程序，也可以指定忽略信号。进程还可以指定当信号发生时系统将采取默认操作。一个信号也可能被阻塞，在这种情况下，它的传输被延迟到解除阻塞之后。交付时要采取的行动是在交付时确定的。通常，信号处理程序在进程的当前堆栈上执行。这可能会在每个处理程序的基础上进行更改，以便在一个特殊的信号堆栈上接收信号。
 信号例程通常使用导致其调用被阻塞的信号执行，但可能还会发生其他信号。全局信号掩码定义当前从传递到进程被阻塞的信号集。进程的信号掩码由其父进程的信号掩码初始化(通常为空)。它可以通过调用sigprocmask(2)进行更改，或者在向进程传递信号时进行更改。
 
 当进程的信号条件出现时，将该信号添加到进程等待的一组信号中。如果信号当前没有被进程阻塞，那么它将被传递到进程。信号可以在进程进入操作系统的任何时候发送(例如，在系统调用、页面错误或陷阱或时钟中断期间)。如果同时准备交付多个信号，则首先交付可能由陷阱引起的任何信号。额外的信号可能同时被处理，每个信号似乎都在它们的第一个指令之前中断前一个信号的处理程序。sigpending(2)函数返回一组挂起的信号。当捕获的信号被传递时，将保存进程的当前状态，计算一个新的信号掩码(如下所述)，并调用信号处理程序。对处理程序的调用是这样安排的:如果信号处理例程正常返回，则进程将从信号交付之前在上下文中恢复执行。如果进程希望在不同的上下文中恢复，则必须安排恢复以前的上下文中本身。
 
 当信号被传递给进程时，在进程的信号处理程序期间(或在调用sigprocmask(2)之前)，将安装一个新的信号掩码。这个掩码是通过将当前信号掩码集、要传递的信号和与要调用的处理程序相关联的信号掩码sa_mask的并集组成的，但始终不包括SIGKILL和SIGSTOP。
 
 
 sigaction()为sig指定的信号分配一个动作。如果act是非零的，它指定一个动作(SIG_DFL、SIG_IGN或一个处理程序例程)和掩码，以便在传递指定的信号时使用。如果oact是非零的，则将向用户返回先前处理信号的信息。
 
 一旦安装了信号处理程序，它通常保持安装状态，直到执行另一个sigaction()调用，或者执行execve(2)。sa_handler的值(或者，如果设置了SA_SIGINFO标志，则改为sa_sigaction的值)指示当信号到达时应该执行什么操作。通过将sa_handler设置为SIG_DFL，可以重置特定于信号的默认操作。另外，如果设置了sa_rese标志，则在首次发出信号时将恢复默认操作。默认值是进程终止，可能带有核心转储;没有行动;停止过程;或者继续这个过程。对于每个信号的默认操作，请参见下面的信号列表。如果sa_handler是SIG_DFL，信号的默认操作是丢弃信号，如果信号是挂起的，即使信号被屏蔽，挂起的信号也会被丢弃。如果将sa_handler设置为SIG_IGN，则会忽略和丢弃信号的当前和挂起实例。如果sig是SIGCHLD，并且sa_handler被设置为SIG_IGN，则会隐含SA_NOCLDWAIT标志(如下所述)。
 */

#import "CrashReporter.h"
#import "PLCrashAsync.h"
#import "PLCrashSignalHandler.h"
#import "PLCrashFrameWalker.h"
#import "PLCrashReporterNSError.h"

#import "PLCrashAsyncLinkedList.hpp"

#import <signal.h>
#import <unistd.h>

using namespace plcrash::async;

/**
 * @internal
 *
 * Manages the internal state for a user-registered callback and context.
 */
struct plcrash_signal_user_callback {
    /** Signal handler callback function. */
    PLCrashSignalHandlerCallbackFunc callback;
    
    /** Signal handler context. */
    void *context;
};

/**
 * @internal
 *
 * A signal handler callback context.
 */
struct PLCrashSignalHandlerCallback {
    /**
     * Internal callback function. This function is responsible for determining the next
     * signal handler in the chain of handlers, and issueing the actual PLCrashSignalHandlerCallback()
     * invocation.
     */
    bool (*callback)(int signo, siginfo_t *info, ucontext_t *uap, void *context);

    /** Signal handler context. */
    void *context;
};

/**
 * @internal
 *
 * A registered POSIX signal handler action. This is used to represent previously
 * registered signal handlers that have been replaced by the PLCrashSignalHandler's
 * global signal handler.
 */
struct plcrash_signal_handler_action {
    /** Signal type. */
    int signo;
    
    /** Signal handler action. */
    struct sigaction action;
};

/**
 * Signal handler context that must be global for async-safe
 * access.
 */
static struct {
    /** @internal
     * Registered callbacks. */
    async_list<plcrash_signal_user_callback> callbacks;
    
    /** @internal
     * Originaly registered signal handlers. This list should only be mutated in
     * -[PLCrashSignalHandler registerHandlerWithSignal:error:] with the appropriate locks held. */
    async_list<plcrash_signal_handler_action> previous_actions;
} shared_handler_context;

/*
 * Finds and executes the first matching signal handler in the shared previous_actions list; this is used
 * to support executing process-wide POSIX signal handlers that were previously registered before being replaced by
 * PLCrashSignalHandler::registerHandlerForSignal:.
 */
static bool previous_action_callback (int signo, siginfo_t *info, ucontext_t *uap, void *context, PLCrashSignalHandlerCallback *nextHandler) {
    bool handled = false;

    /* Let any additional handler execute 如果在PLC注册信号之前，进程内已经有别的handler注册了该信号，那么此处也会递归的调用这些handler*/
    if (PLCrashSignalHandlerForward(nextHandler, signo, info, uap))
        return true;

    /*
     遍历previous_actions的List，如果信号类型能比对上，则调用之前注册时设置的sa_sigaction函数。这里可以对应最初保存别的SDK注册信号的处理：
     */
    shared_handler_context.previous_actions.set_reading(true); {
        /* Find the first matching handler */
        async_list<plcrash_signal_handler_action>::node *next = NULL;
        while ((next = shared_handler_context.previous_actions.next(next)) != NULL) {
            /* Skip non-matching entries */
            if (next->value().signo != signo)
                continue;

            /*
             需要注意的是，遍历的时候，只要信号类型（比如SIGABRT）对的上，那么就去找sa_flags对应的标记，如果你注册的是sigaction的sa_sigaction那么回调这个，如果注册的是sa_handler，则对应进行回调。SIG_IGN表示忽略则不进行额外处理，SIGDFL是一个空函数
             */
            /* Found a match */
            // TODO - Should we handle the other flags, eg, SA_RESETHAND, SA_ONSTACK? */
            if (next->value().action.sa_flags & SA_SIGINFO) {
                next->value().action.sa_sigaction(signo, info, (void *) uap);
                handled = true;
            } else {
                void (*next_handler)(int) = next->value().action.sa_handler;
                if (next_handler == SIG_IGN) {
                    /* Ignored */
                    handled = true;

                } else if (next_handler == SIG_DFL) {
                    /* Default handler should be run, be we have no mechanism to pass through to
                     * the default handler; mark the signal as unhandled. */
                    handled = false;

                } else {
                    /* Handler registered, execute it */
                    next_handler(signo);
                    handled = true;
                }
            }
            //不管怎样，只要找到一个handler处理完毕后就直接break跳出循环了。
            /* Handler was found; iteration done */
            break;
        }
    } shared_handler_context.previous_actions.set_reading(false);

    return handled;
}

/*
 * Recursively iterates the actual callbacks registered in our shared_handler_context. To begin iteration,
 * provide a value of NULL for 'context'.
 */
static bool internal_callback_iterator (int signo, siginfo_t *info, ucontext_t *uap, void *context) {
    /* Call the next handler in the chain. If this is the last handler in the chain, pass it the original signal
     * handlers. */
    bool handled = false;
    //对静态全局变量的callbacks的List进行遍历
    shared_handler_context.callbacks.set_reading(true); {
        //prev指向context。第一次context是外部传入的NULL
        async_list<plcrash_signal_user_callback>::node *prev = (async_list<plcrash_signal_user_callback>::node *) context;
        //当next()函数传入NULL,会返还链表头指针.所以current初始值是list的头结点
        async_list<plcrash_signal_user_callback>::node *current = shared_handler_context.callbacks.next(prev);

        /* Check for end-of-list */
        if (current == NULL) {
            shared_handler_context.callbacks.set_reading(false);
            return false;
        }
        
        /* Check if any additional handlers are registered. If so, provide the next handler as the forwarding target. */
        if (shared_handler_context.callbacks.next(current) != NULL) {
            PLCrashSignalHandlerCallback next_handler = {
                .callback = internal_callback_iterator,
                .context = current
            };
            handled = current->value().callback(signo, info, uap, current->value().context, &next_handler);
        } else {
            /* Otherwise, we've hit the final handler in the list. */
            handled = current->value().callback(signo, info, uap, current->value().context, NULL);
        }
    } shared_handler_context.callbacks.set_reading(false);

    return handled;
};

/** 
 * @internal
 * 信号处理函数。当崩溃时，最开始的回调入口就是这个函数
 * The signal handler function used by PLCrashSignalHandler. This function should not be called or referenced directly,
 * but is exposed to allow simulating signal handling behavior from unit tests.
 * 除非是单元测试，否则不要手动调用这个函数
 * @param signo The signal number.
 * @param info The signal information.
 * @param uapVoid A ucontext_t pointer argument.
 */
void plcrash_signal_handler (int signo, siginfo_t *info, void *uapVoid) {
    /* Start iteration; we currently re-raise the signal if not handled by callbacks; this should be revisited 如果崩溃发生时，callbacks的List里，没有任何人来处理这个收到的信号，则会重新把该信号抛出来
     * in the future, as the signal may not be raised on the expected thread.
     */
    if (!internal_callback_iterator(signo, info, (ucontext_t *) uapVoid, NULL))
        raise(signo);
}

/**
 * Forward a signal to the first matching callback in @a next, if any.
 *
 * @param next The signal handler callback to which the signal should be forwarded. This value may be NULL,
 * in which case false will be returned.
 * @param sig The signal number.
 * @param info The signal info.
 * @param uap The signal thread context.
 *
 * @return Returns true if the exception was handled by a registered signal handler, or false
 * if the exception was not handled, or no signal handler was registered for @a signo.
 *
 * @note This function is async-safe.
 */
bool PLCrashSignalHandlerForward (PLCrashSignalHandlerCallback *next, int sig, siginfo_t *info, ucontext_t *uap) {
    if (next == NULL)
        return false;

    return next->callback(sig, info, uap, next->context);
}

/***
 * @internal
 *
 * Manages a process-wide signal handler, including async-safe registration of multiple callbacks, and pass-through
 * to previously registered signal handlers.
 *
 * @todo Remove the signal handler's registered callbacks from the callback chain when the instance is deallocated.
 */
@implementation PLCrashSignalHandler

/* Shared signal handler. Since signal handlers are process-global, it would be unusual
 * for more than one instance to be required. */
static PLCrashSignalHandler *sharedHandler;

+ (void) initialize {
    if ([self class] != [PLCrashSignalHandler class])
        return;
    
    sharedHandler = [[self alloc] init];
}

/**
 * Return the shared signal handler.
 */
+ (PLCrashSignalHandler *) sharedHandler {
    return sharedHandler;
}

/**
 * @internal
 *
 * Reset <em>all</em> currently registered callbacks. This is primarily useful for testing purposes,
 * and should be avoided in production code.
 */
+ (void) resetHandlers {
    /* Reset all saved signal handlers */
    shared_handler_context.previous_actions.set_reading(true); {
        async_list<plcrash_signal_handler_action>::node *next = NULL;
        while ((next = shared_handler_context.previous_actions.next(next)) != NULL)
            shared_handler_context.previous_actions.nasync_remove_node(next);
    } shared_handler_context.previous_actions.set_reading(false);

    /* Reset all callbacks */
    shared_handler_context.callbacks.set_reading(true); {
        async_list<plcrash_signal_user_callback>::node *next = NULL;
        while ((next = shared_handler_context.callbacks.next(next)) != NULL)
            shared_handler_context.callbacks.nasync_remove_node(next);
    } shared_handler_context.callbacks.set_reading(false);
}

/**
 * Initialize a new signal handler instance.
 *
 * API clients should generally prefer the +[PLCrashSignalHandler sharedHandler] method.
 */
- (id) init {
    if ((self = [super init]) == nil)
        return nil;
    
    /* Set up an alternate signal stack for crash dumps. Only 64k is reserved, and the
     * crash dump path must be sparing in its use of stack space. */
    _sigstk.ss_size = MAX(MINSIGSTKSZ, 64 * 1024);
    _sigstk.ss_sp = malloc(_sigstk.ss_size);
    _sigstk.ss_flags = 0;

    /* (Unlikely) malloc failure */
    if (_sigstk.ss_sp == NULL) {
        [self release];
        return nil;
    }

    return self;
}

/**
 * Register a signal handler for the given @a signo, if not yet registered. If a handler has already been registered,
 * no changes will be made to the existing handler.
 *
 * We register only one signal handler for any given signal number; All instances share the same async-safe/thread-safe
 * ordered list of callbacks.
 *
 * @param signo The signal number for which a handler should be registered.
 * @param outError A pointer to an NSError object variable. If an error occurs, this
 * pointer will contain an error object indicating why the signal handlers could not be
 * registered. If no error occurs, this parameter will be left unmodified.
 */
- (BOOL) registerHandlerWithSignal: (int) signo error: (NSError **) outError {
    static pthread_mutex_t registerHandlers = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&registerHandlers); {
        static BOOL singleShotInitialization = NO;

        /* Perform operations that only need to be done once per process.
         */
        if (!singleShotInitialization) {
            /*
             *  注册我们的信号栈。现在，我们在调用线程上注册我们的信号堆栈;将来，这可能会转移到一个公开的实例方法中，以便允许在任何线程上注册自定义信号堆栈。目前，这支持在启用信号处理程序的线程上注册信号堆栈的遗留行为。
             * Register our signal stack. Right now, we register our signal stack on the calling thread; this may,
             * in the future, be moved to an exposed instance method, as to allow registering a custom signal stack on any thread.
             *
             * For now, this supports the legacy behavior of registering a signal stack on the thread on
             * which the signal handlers are enabled.
            http://www.groad.net/bbs/forum.php?mod=viewthread&tid=7336
             */
            //sigaltstack()允许用户定义一个备用堆栈，在此堆栈上处理传递给该线程的信号 只有成功返回0
            // https://man.openbsd.org/sigaltstack.2
            if (sigaltstack(&_sigstk, 0) < 0) {
                /* This should only fail if we supply invalid arguments to sigaltstack() */
                plcrash_populate_posix_error(outError, errno, @"Could not initialize alternative signal stack");
                return NO;
            }
            
            /*
             * Add the pass-through sigaction callback as the last element in the callback list.
             */
            plcrash_signal_user_callback sa = {
                .callback = previous_action_callback,
                .context = NULL
            };
            //而注册函数内部的append函数的操作，其结构体的context是NULL，然后callback是 previous_action_callback，而不是传进来的callback，其是把一个新的结构体，插入到callbacks的List的最后面
            //这样当信号进入时，previous_action_callback和之前的callback都会被调用
            shared_handler_context.callbacks.nasync_append(sa);
        }
        
        /* Check whether the signal already has a registered handler. */
        BOOL isRegistered = NO;
        shared_handler_context.previous_actions.set_reading(true); {
            /* Find the first matching handler */
            async_list<plcrash_signal_handler_action>::node *next = NULL;
            while ((next = shared_handler_context.previous_actions.next(next)) != NULL) {
                if (next->value().signo == signo) {
                    isRegistered = YES;
                    break;
                }
            }
        } shared_handler_context.previous_actions.set_reading(false);

        /* Register handler for the requested signal */
        if (!isRegistered) {
            struct sigaction sa;
            struct sigaction sa_prev;
            
            /* Configure action */
            memset(&sa, 0, sizeof(sa));
            sa.sa_flags = SA_SIGINFO|SA_ONSTACK;
            sigemptyset(&sa.sa_mask);
            //sa_sigaction是取了plcrash_signal_handler这个函数的地址.当信号过来时，会回调赋值给sa变量的sa_sigaction
            sa.sa_sigaction = &plcrash_signal_handler;
            
            /* Set new sigaction 注册信号使用的函数sigaction*/
            if (sigaction(signo, &sa, &sa_prev) != 0) {
                int err = errno;
                plcrash_populate_posix_error(outError, err, @"Failed to register signal handler");
                return NO;
            }
            /*
             WARNING: 但是如果该信号之前被别的SDK注册过，PLC会保存下来，之后当异常信号发生时再统一进行回调，这里是把之前别的SDK注册该信号的handler添加到了shared_handler_context.previous_actions的List里：
             
             */
            /* Save the previous action. Note that there's an inescapable race condition here, such that
             * we may not call the previous signal handler if signal occurs prior to our saving
             * the caller's handler.
             * 保存前面的操作。注意，这里有一个不可避免的竞态条件，如果信号发生在保存调用方的处理程序之前，则不能调用前面的信号处理程序
             TODO: 研究使用异步安全锁定来避免这种情况。请参见:PLCrashReporter类支持Mach异常。
             * TODO - Investigate use of async-safe locking to avoid this condition. See also:
             * The PLCrashReporter class's enabling of Mach exceptions.
             */
            plcrash_signal_handler_action act = {
                .signo = signo,
                .action = sa_prev
            };
            shared_handler_context.previous_actions.nasync_append(act);
        }
    } pthread_mutex_unlock(&registerHandlers);
    
    return YES;
}

/**
 * Register a new signal @a callback for @a signo.
 *
 * @param signo The signal for which a signal handler should be registered. Note that multiple callbacks may be registered
 * for a single signal, with chaining handled appropriately by the receiver. If multiple callbacks are registered, they may
 * <em>optionally</em> forward the signal to the next callback (and the original signal handler, if any was registered) via PLCrashSignalHandlerForward.
 * @param callback Callback to be issued upon receipt of a signal. The callback will execute on the crashed thread.
 * @param context Context to be passed to the callback. May be NULL.
 * @param outError A pointer to an NSError object variable. If an error occurs, this pointer will contain an error object indicating why
 * the signal handlers could not be registered. If no error occurs, this parameter will be left unmodified. You may specify
 * NULL for this parameter, and no error information will be provided.
 *
 * @warning Once registered, a callback may not be deregistered. This restriction may be removed in a future release.
 * @warning Callers must ensure that the PLCrashSignalHandler instance is not released and deallocated while callbacks remain active; in
 * a future release, this may result in the callbacks also being deregistered.
 */
- (BOOL) registerHandlerForSignal: (int) signo
                         callback: (PLCrashSignalHandlerCallbackFunc) callback
                          context: (void *) context
                            error: (NSError **) outError
{
    /* Register the actual signal handler, if necessary */
    if (![self registerHandlerWithSignal: signo error: outError])
        return NO;
    
    /* Add the new callback to the shared state list.
     回调函数被保存到一个全局静态变量shared_handler_context.callbacks中
     */
    plcrash_signal_user_callback reg = {
        .callback = callback,
        .context = context
    };
    //prepend函数是把传进来的callback和context封装的结构体插入到了callbacks的List的最前面的位置。
    shared_handler_context.callbacks.nasync_prepend(reg);
    
    return YES;
}

@end
