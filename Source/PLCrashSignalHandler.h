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

#import <Foundation/Foundation.h>
#import "PLCrashMacros.h"

PLCR_C_BEGIN_DECLS

typedef struct PLCrashSignalHandlerCallback PLCrashSignalHandlerCallback;

/**
 * @internal
 * Signal handler callback function
 * 定义了一个PLCrashSignalHandlerCallbackFunc指针变量，它指向某个函数的指针，这个函数参数是int signo, siginfo_t *info, ucontext_t *uap, void *context, PLCrashSignalHandlerCallback *next)，返回值是bool。
 * @param signo The received signal.
 * @param info The signal info.
 * @param uap The signal thread context.
 * @param context The previously specified context for this handler.
 * @param next A borrowed reference to the next signal handler's callback, or NULL if this is the final registered callback.
 * May be used to forward the signal via PLCrashSignalHandlerForward.
 *
 * @return Return true if the signal was handled and execution should continue, false if the signal was not handled.
 */
typedef bool (*PLCrashSignalHandlerCallbackFunc)(int signo, siginfo_t *info, ucontext_t *uap, void *context, PLCrashSignalHandlerCallback *next);

void plcrash_signal_handler (int signo, siginfo_t *info, void *uapVoid);

bool PLCrashSignalHandlerForward (PLCrashSignalHandlerCallback *next, int signal, siginfo_t *info, ucontext_t *uap);

@interface PLCrashSignalHandler : NSObject {
@private
    /*
     //SA_ONSTACK: 如果在从当前建立的“可替换信号栈”(old_sigstack)中获取相关信息时设置该标志，那么表示进程当前正在“可替换信号栈”中执行，如果此时试图去建立一个新的“可替换信号栈”，那么会遇到 EPERM (禁止该动作) 的错误
     
     //SA_DISABLE:
     如果在返回的 old_sigstack 中看到此标志，那么说明当前没有已建立的“可替换信号栈”。如果在 sigstack 中指定该标志，那么当前禁止建立“可替换信号栈”
     _STRUCT_SIGALTSTACK
     {
        void            *ss_sp;//栈顶指针
        __darwin_size_t ss_size;//栈空间大小
        int             ss_flags;//栈空间标志位 SA_DISABLE and/or SA_ONSTACK
        };
     
     */
    /** Signal stack 信号栈*/
    stack_t _sigstk;
}


+ (PLCrashSignalHandler *) sharedHandler;

+ (void) resetHandlers;

- (BOOL) registerHandlerForSignal: (int) signo
                         callback: (PLCrashSignalHandlerCallbackFunc) callback
                          context: (void *) context
                            error: (NSError **) outError;

@end

PLCR_C_END_DECLS
