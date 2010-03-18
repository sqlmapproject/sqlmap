.CODE
__exec_payload PROC x:QWORD
   mov rax, x
   call QWORD PTR[rax]
   ret
__exec_payload ENDP 
END 
