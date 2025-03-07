/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 * This file was created by Manorit Chawdhry.                              *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/


#include <libinjector/debug_helpers.h>

#include "linux_execve.h"
#include "linux_syscalls.h"

static event_response_t cleanup(injector_t injector, x86_registers_t* regs);
bool create_argv_and_envp_arrays(injector_t injector, x86_registers_t* regs, size_t mmap_size, addr_t* argv_addr, addr_t* envp_addr);
bool is_child_process(injector_t injector,  drakvuf_trap_info_t* info)
{
    if (info->proc_data.ppid == injector->target_pid)
    {
        PRINT_DEBUG("Inside child process\n");
        return true;
    }
    PRINT_DEBUG("Inside parent process: %d\n", info->proc_data.pid);
    PRINT_DEBUG("Step of injector: %d\n", injector->step + 1);
    return false;
}

/* This function handles execve syscalls, it does so in a total of 5 steps
 *
 * STEP1:
 * It initialises the syscalls and then it calls mmap to reserve some space for keeping
 * the string arguments to be passed in execve
 *
 * STEP2:
 * This step vforks the process and loosens the check around check_userspace_int3_trap
 * but setting injector->fork = true. This helps us get the pid of the child process
 * as soon as we get it, we use that child pid to tighten the checks again
 *
 * STEP3:
 * We get the pid in this as this trap should only hit in the child process as per the
 * checks in check_userspace_int3_trap. So we can now store the pid of the child process
 * and setup execve calls
 *
 * STEP4:
 * This step is considered a part of the cleanup, It checks if execve succeeded or not,
 * if it did not then it will exit the child process and then keep the step so that we
 * can restore the parent process in the next callback. If the child process executes
 * execve successfully, parent process gets active again and we hit parent process
 * restoring it's state
 *
 * STEP6:
 * We free the initial trap and interrupt drakvuf
 */
event_response_t handle_execve(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    event_response_t event;

    switch (injector->step)
    {
        case STEP1: // Finds vdso and sets up mmap
        {
            memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

            if (!init_syscalls(drakvuf, info))
                return override_step(injector, STEP5, VMI_EVENT_RESPONSE_NONE);

            // don't remove the initial trap
            // it is used for cleanup after restoring registers

            if (!setup_mmap_syscall(injector, info->regs, FILE_BUF_SIZE))
            {
                // clear post_syscall_trap
                free_bp_trap(drakvuf, injector, injector->bp);
                return override_step(injector, STEP5, VMI_EVENT_RESPONSE_NONE);
            }

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;

            break;
        }
        case STEP2: // forks the process
        {
            if (!call_mmap_syscall_cb(injector, info->regs))
                return cleanup(injector, info->regs);

            char* proc_name = strdup(info->proc_data.name);

            PRINT_DEBUG("vForking the process\n");
            setup_vfork_syscall(injector, info->regs, proc_name, info->proc_data.pid);

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3: // get child pid and runs execve
        {
            if (!call_vfork_syscall_cb(injector, info->regs, info->proc_data.pid, info->proc_data.tid))
                return cleanup(injector, info->regs);

            addr_t argv_addr, envp_addr;

            if (!create_argv_and_envp_arrays(injector, info->regs, FILE_BUF_SIZE, &argv_addr, &envp_addr))
                return cleanup(injector, info->regs);

            if (!setup_execve_syscall(injector, info->regs, injector->host_file, argv_addr, envp_addr))
                return cleanup(injector, info->regs);

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4: // handles execve and restores parent
        {
            if (is_child_process(injector, info))
            {
                is_syscall_error(info->regs->rax, "execve syscall failed");

                PRINT_DEBUG("Exiting child process\n");
                if (!setup_exit_syscall(injector, info->regs, 0))
                {
                    fprintf(stderr, "Fatal error: Could not cleanup properly\n");
                    drakvuf_interrupt(drakvuf, SIGINT);
                    return VMI_EVENT_RESPONSE_NONE;
                }

                // this is being done so that the parent can also be cleared
                return override_step(injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
            }
            else
            {
                PRINT_DEBUG("Restoring parent registers\n");
                memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

                // free the post_syscall_trap
                free_bp_trap(drakvuf, injector, info->trap);
            }

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;

        }
        case STEP5: // exit drakvuf loop
        {
            if (is_child_process(injector, info))
            {
                fprintf(stderr, "Assertion: Should never happen, Child process alive\n");
                drakvuf_interrupt(drakvuf, SIGINT);
                return VMI_EVENT_RESPONSE_NONE;
            }

            PRINT_DEBUG("Removing traps and exiting\n");

            // remove the initial trap here
            free_bp_trap(drakvuf, injector, info->trap);
            drakvuf_interrupt(drakvuf, SIGINT);

            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return event;
}

addr_t create_argv_array(injector_t injector, x86_registers_t* regs, addr_t* data_addr, addr_t* array_addr)
{
    struct argument arg; // this will be passed in place_array_on_addr_64
    struct argument* argv = g_new0(struct argument, injector->args_count + 2);

    // argv = [binary_file, args..., NULL];
    init_string_argument(&argv[0], injector->host_file);

    PRINT_DEBUG("Total arguments: %d\n", injector->args_count);
    for (int i=0; i<injector->args_count; i++)
    {
        init_string_argument(&argv[i+1], injector->args[i]);
        PRINT_DEBUG("Args %d: %s\n", i, injector->args[i]);
    }

    init_int_argument(&argv[injector->args_count+1], 0); // null in the end
    init_array_argument(&arg, argv, injector->args_count + 2);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

    *array_addr = place_array_on_addr_64(vmi, regs, &arg, data_addr, array_addr);
    if (*array_addr == 0)
        goto err;

    g_free(argv);
    drakvuf_release_vmi(injector->drakvuf);
    return arg.data_on_stack;
err:
    fprintf(stderr, "Could not create argv arrays\n");
    g_free(argv);
    drakvuf_release_vmi(injector->drakvuf);
    return 0;
}

addr_t create_envp_array(injector_t injector, x86_registers_t* regs, addr_t* data_addr, addr_t* array_addr)
{
    struct argument arg; // this will be passed in place_array_on_addr_64

    // TODO: allow passing envp arguments through cli
    struct argument envp[1];

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

    // envp = [NULL];
    init_int_argument(&envp[0], 0); // null
    init_array_argument(&arg, envp, 1);

    *array_addr = place_array_on_addr_64(vmi, regs, &arg, data_addr, array_addr);
    if (*array_addr == 0)
        goto err;

    drakvuf_release_vmi(injector->drakvuf);
    return arg.data_on_stack;
err:
    fprintf(stderr, "Could not create envp arrays\n");
    drakvuf_release_vmi(injector->drakvuf);
    return 0;
}

bool create_argv_and_envp_arrays(injector_t injector, x86_registers_t* regs, size_t mmap_size, addr_t* argv_addr, addr_t* envp_addr)
{
    addr_t data_addr = injector->virtual_memory_addr + mmap_size;
    addr_t array_addr = injector->virtual_memory_addr + mmap_size/2;

    if ((*argv_addr = create_argv_array(injector, regs, &data_addr, &array_addr)) == 0)
        return false;

    if ((*envp_addr = create_envp_array(injector, regs, &data_addr, &array_addr)) == 0)
        return false;

    return true;
}

/* This function handles cleanup incase something goes wrong. This seems to be a difficult
 * task compared to other methods as this time there is also a child process that we need
 * to exit in case of some error. For this, we will be going to STEP4. STEP4 handles the
 * cleanup of both the parent as well as the child process.
 */
static event_response_t cleanup(injector_t injector, x86_registers_t* regs)
{
    fprintf(stderr, "Doing premature cleanup\n");

    memcpy(regs, &injector->saved_regs, sizeof(x86_registers_t));

    return override_step(injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
}
