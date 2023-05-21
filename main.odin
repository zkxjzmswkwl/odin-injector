package main

import "core:fmt"
import "core:strings"
import w "core:sys/windows"

foreign import k32 "system:kernel32.lib"

process_entry :: struct {
	dwSize: w.DWORD
	cntUsage: w.DWORD
	th32ProcessID: w.DWORD
	th32DefaultHeapID: w.ULONG_PTR
	th32ModuleID: w.DWORD
	cntThreads: w.DWORD
	pcPriClassBase: w.LONG
	dwFlags: w.DWORD
	szExeFile: [260]w.CHAR
}


foreign k32 {

	CreateToolhelp32Snapshot :: proc(dwFlags: w.DWORD, th32ProcessID: w.DWORD) -> w.HANDLE ---
	Process32First :: proc(hSnapshot: w.HANDLE, lppe: ^process_entry) -> int     ---
	Process32Next :: proc(hSnapshot: w.HANDLE, lppe: ^process_entry) -> int     ---
	OpenProcess :: proc(dwDesiredAccess: u32, bInheritHandle: int, dwProcessId: u32) -> w.HANDLE ---
}


enum_w_callback :: proc(hwnd: w.HWND, lparam: w.LPARAM) {
	fmt.println("enum_w_callback")
}

filter_processes :: proc(file_name: string) -> u32 {
	fmt.println("filter_processes")

	process_id: w.DWORD
	pe32: process_entry
	pe32.dwSize = size_of(process_entry)

	snapshot_handle := CreateToolhelp32Snapshot(0x00000002, 0)

	if Process32First(snapshot_handle, &pe32) == 0 {
		fmt.println("k32.Process32First failed.")
	}

	for Process32Next(snapshot_handle, &pe32) == 1 {
		remote_buffer: strings.Builder
		strings.builder_init(&remote_buffer)

		for c, idx in pe32.szExeFile {
			strings.write_byte(&remote_buffer, c)
		}

		built_str := strings.to_string(remote_buffer)

		if strings.contains(built_str, file_name) {
			fmt.println("Found the rs2 process.")
			process_id = pe32.th32ProcessID
			break
		} 
	}

	w.CloseHandle(snapshot_handle)
	return process_id
}

inject_dll :: proc(process_id: u32, module_path: string) {
	fmt.println(strings.clone_to_cstring(module_path))
	proc_handle := OpenProcess(0x000F000 | 0x00100000 | 0xFFFF, 0, process_id)
	load_library := cast(proc "stdcall" (rawptr) -> u32)w.GetProcAddress(w.GetModuleHandleA("kernel32.dll"), "LoadLibraryA")

	remote := w.VirtualAllocEx(proc_handle, nil, len(module_path), w.MEM_RESERVE | w.MEM_COMMIT, w.PAGE_READWRITE)
	w.WriteProcessMemory(proc_handle, remote, rawptr(strings.clone_to_cstring(module_path)), len(module_path), nil)
	w.CreateRemoteThread(proc_handle, nil, 0, load_library, remote, 0, nil)
	w.CloseHandle(proc_handle)
}

main :: proc() {
	process_id := filter_processes("rs2client.exe")
	fmt.println(process_id)
	inject_dll(process_id, "C:/Users/Carter/petergriffin/build/RelWithDebInfo/PeterGriffin.dll")
}
