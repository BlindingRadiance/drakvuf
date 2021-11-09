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
***************************************************************************/

#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>
#include <json-c/json_object.h> 

#include "spraymon.h"
#include "private.h"
#include "plugins/output_format.h"

#define PRINT_SPRAYMON(...) \
    do { \
        if(verbose) { \
            eprint_current_time(); \
            fprintf (stderr, __VA_ARGS__); \
        }\
    } while (0)

// #define PRINT_SPRAYMON(...) \
//     do { \
//         eprint_current_time(); \
//         fprintf (stderr, __VA_ARGS__); \
//     } while (0)


bool spraymon::read_counter(drakvuf_t drakvuf, addr_t vaddr, vmi_pid_t pid, uint16_t* value)
{
    vmi_lock_guard vmi(drakvuf);
    if( VMI_SUCCESS != vmi_read_16_va(vmi, vaddr, pid, value))
    {
        return false;
    }
    return true;
}

bool spraymon::read_kernel_addr(drakvuf_t drakvuf, addr_t in_address, vmi_pid_t pid, addr_t * out_address)
{
    vmi_lock_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_va(vmi, in_address, pid, sizeof(addr_t), out_address, NULL))
    {
        return false;
    }
    return true;
}

bool spraymon::check_counters(drakvuf_t drakvuf, addr_t process, vmi_pid_t pid, uint16_t * gdi_max_count, uint16_t* usr_max_count)
{
    addr_t win32process;

    if (!read_kernel_addr(drakvuf, process + this->Eprocess_Win32Process, pid, &win32process))
    {
        PRINT_SPRAYMON("[SPRAYMON] Failed to read EPROCESS->Win32Process\n");
        return false;
    }
     
    if (!win32process)
    {
        PRINT_SPRAYMON("[SPRAYMON] Win32Process is NULL\n");
        return false;
    }
    if (!read_counter(drakvuf, win32process + this->GDIHandleCountPeak, pid, gdi_max_count))
    {
         PRINT_SPRAYMON("[SPRAYMON] Failed to read GDI peak handle count\n");
         return false;
    }
    
    if (!read_counter(drakvuf, win32process + this->UserHandleCountPeak, pid, usr_max_count))
    {
         PRINT_SPRAYMON("[SPRAYMON] Failed to read USER peak handle count\n");
         return false;
    }

    return true;
}

void spraymon::compare(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint16_t gdi_max_count,  uint16_t usr_max_count)
{
    if (gdi_max_count > this->gdi_threshold)
    {
        fmt::print(this->format, "spraymon", drakvuf, info,
                    keyval("Reason", fmt::Qstr("High GDI objects count detected!")));
    }

    if (usr_max_count > this->usr_threshold)
    {
        fmt::print(this->format, "spraymon", drakvuf, info,
                    keyval("Reason", fmt::Qstr("High USER objects count detected!")));
    }
}

static void process_visitor(drakvuf_t drakvuf, addr_t process, void * ctx)
{
    auto eprocess_list = static_cast<std::vector<addr_t>*>(ctx);
    eprocess_list->push_back(process);
}

event_response_t spraymon::final_analysis_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto process_list = new std::vector<addr_t>;

    vmi_pid_t pid;
    uint16_t gdi_max_count;
    uint16_t usr_max_count;

    if (this->is_stopping() && !this->done_final_analysis)
    {
        PRINT_SPRAYMON("[SPRAYMON] Starting final analysis\n");
        drakvuf_enumerate_processes(drakvuf, process_visitor, static_cast<void*>(process_list));
        for (const auto& process : *process_list)
        {
            gdi_max_count = 0;
            usr_max_count = 0;
            auto temp_attach_data = info->attached_proc_data;
            auto temp_data = info->proc_data;

            proc_data_t data = {};
            if (!drakvuf_get_process_data(drakvuf, process, &data))
            {
                PRINT_SPRAYMON("[SPRAYMON] Failed to get process data.\n");
                continue;
            }
            if (!drakvuf_get_process_pid(drakvuf, process, &pid))
            {
                PRINT_SPRAYMON("[SPRAYMON] Failed to get process pid.\n");
                continue;
            }
   
            info->attached_proc_data = data;
            info->proc_data = data;

            if (!check_counters(drakvuf, process, pid, &gdi_max_count, &usr_max_count))
            {
                PRINT_SPRAYMON("[SPRAYMON] Process name -> %s\n", data.name);
                continue;
            }
            compare(drakvuf, info, gdi_max_count, usr_max_count);

            PRINT_SPRAYMON("[SPRAYMON] Process name -> %s\nGDI count -> %du\nUSER count -> %du\n", 
                        data.name, gdi_max_count, usr_max_count);

            g_free(const_cast<char*>(data.name));

            info->attached_proc_data = temp_attach_data;
            info->proc_data = temp_data;
        }
        delete process_list;
        this->done_final_analysis = true;     
    }  
    return VMI_EVENT_RESPONSE_NONE;
}


event_response_t spraymon::terminate_user_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{ 
    addr_t process = info->attached_proc_data.base_addr;
    auto pid =  info->proc_data.pid;
    uint16_t gdi_max_count;
    uint16_t usr_max_count;

    char * proc_name;
    proc_name = drakvuf_get_process_name(drakvuf, process, false);
    if (!check_counters(drakvuf, process, pid, &gdi_max_count, &usr_max_count))
    {  
        PRINT_SPRAYMON("[SPRAYMON] Process name -> %s\n", proc_name);
        return VMI_EVENT_RESPONSE_NONE;
    }
    compare(drakvuf, info, gdi_max_count, usr_max_count);


    PRINT_SPRAYMON("[SPRAYMON] Process name -> %s\nGDI count -> %du\nUSER count -> %du\n", 
                    proc_name, gdi_max_count, usr_max_count);
    if (proc_name) g_free(proc_name);
    
    return VMI_EVENT_RESPONSE_NONE;
}

spraymon::spraymon(drakvuf_t drakvuf,  const spraymon_config* config, output_format_t output)
    : pluginex(drakvuf, output), format(output), done_final_analysis(false)
{
    this->gdi_threshold = config->gdi_threshold;
    this->usr_threshold = config->usr_threshold;
    if (!config->win32k_profile)
    {
        PRINT_SPRAYMON("[SPRAYMON] Win32k json profile required to run the plugin.\n");
        throw -1;
    }
    json_object * win32k_profile = json_object_from_file(config->win32k_profile);
    if (!win32k_profile)
    {
        PRINT_SPRAYMON("[SPRAYMON] Failed to load JSON debug info for win32k.sys.\n");
        throw -1;
    }

    // Collect win32k offsets
    if (!json_get_struct_member_rva(drakvuf, win32k_profile, "_W32PROCESS", "GDIHandleCountPeak", &this->GDIHandleCountPeak) || 
       !json_get_struct_member_rva(drakvuf, win32k_profile, "_W32PROCESS", "UserHandleCountPeak", &this->UserHandleCountPeak)       
      )
    {
        PRINT_SPRAYMON("[SPRAYMON] Failed to win32k members offsets.\n");
        throw -1;
    }
    
    // Collect kernel struct member offsets
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_EPROCESS", "Win32Process", &this->Eprocess_Win32Process))
    {
        PRINT_SPRAYMON("[SPRAYMON] Failed to get kernel struct member offsets.\n");
        throw -1;
    }

    syscall = createSyscallHook("NtTerminateProcess", &spraymon::terminate_user_process_hook_cb);
    
    PRINT_SPRAYMON("[SPRAYMON]  PLUGIN STARTED\n");
   
}

spraymon::~spraymon()
{
    destroy_all_traps();
}

bool spraymon::stop()
{
    if (!is_stopping() && !done_final_analysis)
    {
        m_is_stopping = true;
        syscall = createSyscallHook("NtClose", &spraymon::final_analysis_cb);
        // Return status `Pending`
        return false;
    }
    if (!done_final_analysis)
    {
        return false;
    }
    return true;
}