; Cod3ed By 0xNinjaCyclone --> Greetz to Karim Nasser --> (19/12/2024)

.code

; Get Process Environment Block
GetPEB proc
	; Read G Segment register which contains PEB and also TEB 
	mov rax, qword ptr gs:[60h]
	ret
GetPEB endp

; Get length of unicode string
; Input  = RDI -> Address of the string
; Output = RCX 
GetStrLenW proc
	push rax
	push rdi        ; save string pointer
	mov rcx, -1     ; biggest number possible
	xor ax, ax      ; NUL-Terminator
	repne scasw     ; repeat until reach NUL
	not rcx         ; convert to a positive number
	dec rcx         ; we started from -1
	pop rdi         ; restore string pointer
	pop rax
	ret
GetStrLenW endp

; Get length of ansi string
; Input  = RDI -> Address of the string
; Output = RCX 
GetStrLenA proc
	push rax
	push rdi        ; save string pointer
	mov rcx, -1     ; biggest number possible
	xor al, al      ; NUL-Terminator
	repne scasb     ; repeat until reach NUL
	not rcx         ; convert to a positive number
	dec rcx         ; we started from -1
	pop rdi         ; restore string pointer
	pop rax
	ret
GetStrLenA endp

; Compare unicode string 
; Input  = RSI -> Address of the src
;          RDI -> Address of the dest
;          RCX -> Number of the bytes 
; Output = ZF
StrNCmpW proc
	; Save inputs (The operation will destroy them)
	push rsi
	push rdi
	push rcx

	repe cmpsw
	
	; Restore inputs 
	pop rcx
	pop rdi
	pop rsi
	ret
StrNCmpW endp

; Compare ansi string 
; Input  = RSI -> Address of the src
;          RDI -> Address of the dest
;          RCX -> Number of bytes 
; Output = ZF
StrNCmpA proc
	; Save inputs (The operation will destroy them)
	push rsi
	push rdi
	push rcx

	repe cmpsb
	
	; Restore inputs 
	pop rcx
	pop rdi
	pop rsi
	ret
StrNCmpA endp

; Used in GetModuleHandle2 and GetProcAddress2
RequiredDataNotFound proc
	xor rax, rax          ; Return NULL if we didn't find the required data
	ret
RequiredDataNotFound endp

; Get Module Base Address 
GetModuleHandleW2 proc
	mov rdi, rcx              ; Module name
	call GetStrLenW           ; Get module name length
	call GetPEB               ; Get Process Environment Block 
	mov rax, [rax + 18h]      ; pPEB->pLdr
	lea rax, [rax + 20h]      ; &pLdr->InMemoryOrderModuleList
	                          ; We point to the first node in the list
	mov rbx, rax              ; Save first node address 
	
	NEXT_MODULE:
	cld                       ; Clear Direction Flag
	mov rax, [rax]            ; Move to the next node in the list 
	cmp rax, rbx              ; Check if we reach last node, first == last->next
	jz RequiredDataNotFound
	mov rsi, [rax + 50h]      ; Get unicode module name
	call StrNCmpW             ; Compare current dll name with required dll name
	jnz NEXT_MODULE           ; Search until find required module

	mov rax, [rax + 20h]      ; Get dll base address
	ret
GetModuleHandleW2 endp

; Get Procedure Address from a dll
GetProcAddress2 proc
	mov rdi, rdx                     ; Procedure name
	mov rdx, rcx                     ; Dll Base Address
	call GetStrLenA                  ; Get Length of required function name
	mov eax, dword ptr [rdx + 3Ch]   ; NT Headers RVA
	add rax, rdx                     ; DllBaseAddress + DOS->e_lfanew
	mov eax, dword ptr [rax + 88h]   ; Export Table RVA
	                                 ; IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->VirtualAddress
	test rax, rax                    ; Check if no exports address
	jz RequiredDataNotFound

	add rax, rdx                     ; DllBaseAddress + ExportVirtualAddress
	push rcx                         ; Save procedure name length in the stack
	mov cx, word ptr [rax + 18h]     ; NumberOfNames
	mov r8d, dword ptr [rax + 20h]   ; AddressOfNames RVA
	add r8, rdx                      ; Add base address

	NEXT_FUNCTION:
	mov esi, [r8 + rcx * 4h]         ; Get procedure name RVA
	add rsi, rdx                     ; Add base address
	pop rbx                          ; Restore procedure name length from the stack
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	call StrNCmpA                    ; Compare current function name with required function name
	jz FOUND                         ; Jump if we found the required function 
	xchg rbx, rcx                    ; Back function length and number of function names again
	push rbx                         ; Save function name length in the stack
	loop NEXT_FUNCTION

	; Required function doesn't exist in this dll
	pop rbx
	jmp RequiredDataNotFound

	FOUND:
	; Check if the length of the found function equal required function length
	xchg rsi, rdi                    ; Toggling between current function name and required function name
	                                 ; because GetStrLenA takes rdi as a parameter
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	push rbx                         ; Save required function name length
	push rcx                         ; Save number of function names
	call GetStrLenA                  ; Get length of current function name
	cmp rcx, rbx                     ; CurrentFunctionLength == RequiredFunctionLength ?
	pop rcx                          ; Restore number of function names
	xchg rsi, rdi                    ; back them again
	jnz NEXT_FUNCTION2               ; If length of both not same we should dig deeper
	                                 ; Maybe we were comparing some thing like VirtualAlloc and VirtualAllocEx
	                                 ; We had better avoid this cases

	pop rbx
	mov r9d, dword ptr [rax + 24h]   ; AddressOfNameOrdinals RVA
	add r9, rdx                      ; Add base address
	mov cx, word ptr [r9 + 2h * rcx] ; Get required function ordinal
	mov r8d, dword ptr [rax + 1Ch]   ; AddressOfFunctions RVA
	add r8, rdx                      ; Add base address
	mov eax, [r8 + 4h * rcx]         ; Get required function address RVA
	add rax, rdx                     ; Add base address
	ret

	NEXT_FUNCTION2:
	dec rcx                          ; Decrease loop counter 
	jmp NEXT_FUNCTION                ; Dig deeper

GetProcAddress2 endp

end