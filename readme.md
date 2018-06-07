potato cpu stack machine + salt language
========================================

Tools
-----

salt compiler produces c code       `./salt a.slt b.slt -> out.asm`
salty compiler produces assembly    `./salty a.slt b.slt -> out.bin`
tato vm sims the cpu                `./tato out.bin`

Potato CPU
----------

`16 bit stack cpu with shared program/variable memory and serial io
    32 KB RAM
registers
    fp, pc
    data stack: next, top
    pc stack
    fp stack
instructions (16 bit)
    nop                     0000
    lit <i>                 8000+7FFF (32 K unsigned)
    push-static <i>         1000+0FFF push top = mem[i] (2K signed)
    pop-static <i>          2000+0FFF mem[i] = pop top
    push-rel <i>            3000+0FFF push top = mem[fp+i]
    pop-rel <i>             4000+0FFF mem[fp+i] = pop top
    call <i>                6000+0FFF push fp = fp; fp = fp + i; push ret = pc; pc = pop top
    goto <i>                7000+0FFF pc = pc + i
    if-goto <i>             8000+0FFF if (top != 0) pc = pc + i
    push-mem                F001      top = mem[top]
    pop-mem                 F002 etc  mem[top] = next
    putchar                           print pop top
    getchar                           push top (blocking)
    ret                               pc = pop ret; fp = pop fp;
    add                               pop top = top + next
    sub                               pop top = top - next
    neg                               top = -top
    eq                                top = top == next
    lt                                top = top < next
    and                               top = top && next
    or                                top = top || next
    not                               top = !top`

Salt Language
-------------
`parse:
    <def>* EOF
def:
    ARRAY  var <id>:<type>[<arr_size>];
    VAR    var <id>:<type> = <expr>;
    FUNC   func <id><params> <stmts>
    STRUCT struct <id><params>;
params:
    ( (<id>:<typedef>(,*)) )
type: 
    (void | int | char | bool | <struct>)(*)
stmts: 
    { <stmt>* }
stmt:
    LET    let <id>:<typedef> = <expr>;
    ASSIGN <expr> = <expr>;
    WHILE  while (<expr>) <stmts>;
    IF     if (<expr>) <stmts> (else if (<expr>) <stmts>) (else <stmts>)
    BLOCK  <stmts>;
expr:
    UNARY  <expr> (+,-,==,<,&,||) <expr>
    <expr_binary> at bottom precedence
expr_binary:
    BINARY !<expr>
    BINARY -<expr>
    VAR    <id>
    FIELD  <id>.<id>
    INDEX  <id>[<expr>]
    CALL   <id>(<expr>(,<expr>*)) //call/type cast
    VAR    '<id>'
    INIT   { (<expr> (,*)) }
    VAR    "<str>"
    VAR    <int>`



`<arg> <arg> <local> <local> -> <ret> <ret>` etc.
`func foo(x, y) { let a = 1; return a + x + y; }
func bar() { let x = 5; }
func main() { let x = foo(1, 2); bar(); }
@foo:
    lit 1
    pop-rel 2
    push-rel 0
    push-rel 1
    add
    push-rel 2
    add
    ret
@bar:
    lit 5
    pop-rel 0
    ret
@main:
    lit 1
    lit 2
    lit @foo
    call 1
    pop-rel 0
    lit @bar
    call 1`

