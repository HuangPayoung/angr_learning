# angr_ctf

根据题目介绍angr的一些基本用法。

# 题目列表

## 00_angr_find
调用simulation.explore()进行路径探索，指定find参数为目标地址。

## 01_angr_avoid
调用simulation.explore()进行路径探索，指定find参数为目标地址，新增一个avoid参数作为要避开的地址，一旦执行到改地址状态被废弃，提高效率。

## 02_angr_find_condition
调用simulation.explore()进行路径探索，find和avoid两个参数可以用函数来代替。

## 03_angr_symbolic_registers
将寄存器的值符号化，然后运行当前状态至目标，用约束求解符号。

## 04_angr_symbolic_stack
将栈的值符号化，然后运行当前状态至目标，用约束求解符号。

## 05_angr_symbolic_memory
将内存的值符号化，然后运行当前状态至目标，用约束求解符号。

## 06_angr_symbolic_dynamic_memory
将内存的值符号化，然后运行当前状态至目标，用约束求解符号。和上一题差不多，不过动态分配的内存还有劫持掉它的地址，指向我们符号化变量的保存位置。

## 07_angr_symbolic_file
劫持掉文件，将文件内容符号化，然后运行当前状态至目标，用约束求解符号。

## 08_angr_constraints
为避免路径爆炸问题，自己手动逆向来添加约束，然后运行当前状态至目标，用约束求解符号。

## 09_angr_hooks
逆向看看可能路径爆炸的函数，手动hook掉调用该函数的指令地址，然后模仿原函数功能自己编写一个作为代替。

## 10_angr_simprocedures
逆向看看可能路径爆炸的函数，利用函数名进行hook，继承`angr.SimProcedure`类自己编写一个类，写一个run函数代替原函数的功能。

## 11_angr_sim_scanf
现在angr支持scanf函数就没有做了，其实和上一题差不多，也是写一个类去hook scanf函数。

## 12_angr_veritesting
添加一个参数，可以缓解路径爆炸的问题（原理不懂，需要看看论文才能知道）。

## 13_angr_static_binary
针对静态链接的程序进行hook，把一些会造成路径爆炸的库函数，替代成angr自己实现好的函数。

## 14_angr_shared_library
程序调用了共享库的函数，分析对象是动态库。因为开了PIC需要指定加载基址，从目标函数开始路径探索。

## 15_angr_arbitrary_read
不太理解任意读的意思，其实功能是hook掉puts函数，然后检查puts的参数是不是想要的输出。

## 16_angr_arbitrary_write
不太理解任意写的意思，其实功能是hook掉strncpy，然后检查strncpy的参数是不是想往目标地址写目标内容。

## 17_angr_arbitrary_jump
任意地址跳，这个是栈溢出然后能控制到eip，所以eip可能是符号变量，往eip添加约束看看能否求解出来，符合约束也就能跳到该目的地址了。
