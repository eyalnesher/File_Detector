#!/usr/bin/python

import re
import time

# Global variables:

# A dictionary of the registers
registers = {
    "rax": "0x0000000000000000",
    "rbx": "0x0000000000000000",
    "rcx": "0x0000000000000000",
    "rdx": "0x0000000000000000",
    "rsi": "0x0000000000000000",
    "rdi": "0x0000000000000000",
    "rbp": "0x0000000000000000",
    "rsp": "0x0000000000000000",
    "r8": "0x0000000000000000",
    "r9": "0x0000000000000000",
    "r10": "0x0000000000000000",
    "r11": "0x0000000000000000",
    "r12": "0x0000000000000000",
    "r13": "0x0000000000000000",
    "r14": "0x0000000000000000",
    "r15": "0x0000000000000000"
}

flags = [0, 0, 0, 0, 0, 0, 0, 0, 0]

stack = []  # List that present the stack

# The syscalls:
syscalls = {
    0: "The code is reading from a file ",
    1: "The code is writing to a file ",
    2: "The code is opening a file ",
    3: "The code is closing a file "
}

syscounter = {}

# The registers maximum size
MAX_8BIT = 2 ** 8       # 8 bit register
MAX_16BIT = 2 ** 16     # 16 bit register
MAX_32BIT = 2 ** 32     # 32 bit register
MAX_64BIT = 2 ** 64     # 64 bit register


def hex_fill(num, size, w=True):
    """
    Turns the given number to a hex number.
    If the number length smaller than the given size of digits, the function fill the size with zeros.
    :type num: int
    :type size: int
    :type w: bool
    :rtype: str
    :param num: The given number
    :param size: The number of digits the return number has
    :param w: If the parameter "w" is True, the output number will start with "0x". Otherwise, it won't start with "0x".
    """
    hex_num = hex(num)[2:]
    if hex_num[-1] == "L":
        hex_num = hex_num[:-1]
    if w:
        return "0x" + (size - len(hex_num)) * "0" + hex_num
    else:
        return (size - len(hex_num)) * "0" + hex_num


def reg_value(reg):
    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        return int(registers[reg], 16)

    # 32 bit register
    elif re.match(r"e[a-z]{2}", reg, re.I):
        return int(registers["r" + reg[1:]][10:], 16)
    elif re.match(r"r[0-9]{1,2}d", reg, re.I):
        return int(registers[reg[:-1]][10:], 16)

    # 16 bit register
    elif re.match(r"[a-z][xisp]", reg, re.I):
        return int(registers["r" + reg][14:], 16)
    elif re.match(r"r[0-9]{1,2}w", reg, re.I):
        return int(registers[reg[:-1]][14:], 16)

    # 8 bit register
    elif re.match(r"[a-z]h", reg, re.I):
        return int(registers["r" + reg[0] + "x"][14:16], 16)
    elif re.match(r"[abcd]l", reg, re.I):
        return int(registers["r" + reg[0] + "x"][16:], 16)
    elif re.match(r"[a-z]{2}l", reg, re.I):
        return int(registers["r" + reg[:-1]][16:], 16)
    elif re.match(r"r[0-9]{1,2}b", reg, re.I):
        return int(registers["r" + reg[-1]][:16], 16)


def fill_to_2(num, size, s):
    if num < (size / 2):
        return num
    if s == "s":
        return num - size
    elif s == "u":
        return num + size


def mov(reg, value):
    """
    This function replaces the value of a register
    :type reg: str
    :type value: int
    :rtype: bool
    """
    global registers

    # The registers maximum size
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT
    global memory

    # if re.match('[+|-]?\(')

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        registers.update({reg: hex_fill(value % MAX_64BIT, 16)})

    # 32 bit register
    elif re.match(r"e[a-z]{2}", reg, re.I):
        registers.update({"r" + reg[1:]: registers["r" + reg[1:]][:10] + hex_fill(value % MAX_32BIT, 8, False)})
    elif re.match(r"r[0-9]{1,2}d", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:10] + hex_fill(value % MAX_32BIT, 8, False)})

    # 16 bit register
    elif re.match(r"[a-z][xisp]", reg, re.I):
        registers.update({"r" + reg: registers["r" + reg][:14] + hex_fill(value % MAX_16BIT, 4, False)})
    elif re.match(r"r[0-9]{1,2}w", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:14] + hex_fill(value % MAX_16BIT, 4, False)})

    # 8 bit register
    elif re.match(r"[a-z]h", reg, re.I):
        registers.update(
            {"r  " + reg[-2] + "x": registers["r" + reg[-2] + "x"][:14] + hex_fill(
                value % MAX_8BIT, 2, False) + registers["r" + reg[-2] + "x"][16:]})
    elif re.match(r"[abcd]l", reg, re.I):
        registers.update(
            {"r" + reg[-2] + "x": registers["r" + reg[-2] + "x"][:16] + hex_fill(value % MAX_8BIT, 2, False)})
    elif re.match(r"[a-z]{2}l", reg, re.I):
        registers.update(
            {"r" + reg[:-1]: registers["r" + reg[:-1]][:16] + hex_fill(value % MAX_8BIT, 2, False)})
    elif re.match(r"r[0-9]{1,2}b", reg, re.I):
        registers.update(
            {reg[-1]: registers["r" + reg[-1]][:16] + hex_fill(value % MAX_8BIT, 2, False)})

    return True


def add(reg, adding_value):
    """
    This function increases the value of a register
    :type reg: str
    :type adding_value: int
    :rtype: bool
    """
    global registers
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        registers.update({reg: hex_fill((reg_value(reg) + adding_value) % MAX_64BIT, 16)})

    # 32 bit register
    elif re.match(r"e[a-z]{2}", reg, re.I):
        registers.update({"r" + reg[1:]: registers["r" + reg[1:]][:10] + hex_fill(
            (reg_value(reg) + adding_value) % MAX_32BIT, 8, False)})
    elif re.match(r"r[0-9]{1,2}d", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:10] + hex_fill(
            (reg_value(reg) + adding_value) % MAX_32BIT, 8, False)})

    # 16 bit register
    elif re.match(r"[a-z][xisp]", reg, re.I):
        registers.update({"r" + reg: registers["r" + reg][:14] + hex_fill(
            (reg_value(reg) + adding_value) % MAX_16BIT, 4, False)})
    elif re.match(r"r[0-9]{1,2}w", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:14] + hex_fill(
            (reg_value(reg) + adding_value) % MAX_16BIT, 4, False)})

    # 8 bit register
    elif re.match(r"[a-z]h", reg, re.I):
        registers.update(
            {"r" + reg[0] + "x": registers["r" + reg[0] + "x"][:14] + hex_fill(
                (reg_value(reg) + adding_value) % MAX_8BIT, 2, False) + registers["r" + reg[0] + "x"][16:]})
    elif re.match(r"[abcd]l", reg, re.I):
        registers.update(
            {"r" + reg[0] + "x": registers["r" + reg[0] + "x"][:16] + hex_fill(
                (reg_value(reg) + adding_value) % MAX_8BIT, 2, False)})
    elif re.match(r"[a-z]{2}l", reg, re.I):
        registers.update(
            {"r" + reg[-1] + "x": registers["r" + reg[-1] + "x"][:16] + hex_fill(
                (reg_value(reg) + adding_value) % MAX_8BIT, 2, False)})
    elif re.match(r"r[0-9]{1,2}b", reg, re.I):
        registers.update(
            {reg[-1]: registers[reg[-1]][:16] + hex_fill(
                (reg_value(reg) + adding_value) % MAX_8BIT, 2, False)})

    return True


def sub(reg, subtracting_value):
    """
    This function decreases the value of a register
    :type reg: str
    :type subtracting_value: int
    :rtype: bool
    """
    global registers
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        registers.update({reg: hex_fill((reg_value(reg) - subtracting_value) % MAX_64BIT, 16)})

    # 32 bit register
    elif re.match(r"e[a-z]{2}", reg, re.I):
        registers.update({"r" + reg[1:]: registers["r" + reg[1:]][:10] + hex_fill(
            (reg_value(reg) - subtracting_value) % MAX_32BIT, 8, False)})
    elif re.match(r"r[0-9]{1,2}d", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:10] + hex_fill(
            (reg_value(reg) + subtracting_value) % MAX_32BIT, 8, False)})

    # 16 bit register
    elif re.match(r"[a-z][xisp]", reg, re.I):
        registers.update({"r" + reg: registers["r" + reg][:14] + hex_fill(
            (reg_value(reg) - subtracting_value) % MAX_16BIT, 4, False)})
    elif re.match(r"r[0-9]{1,2}w", reg, re.I):
        registers.update({reg[:-1]: registers[reg[:-1]][:14] + hex_fill(
            (reg_value(reg) - subtracting_value) % MAX_16BIT, 4, False)})

    # 8 bit register
    elif re.match(r"[a-z]h", reg, re.I):
        registers.update(
            {"r" + reg[0] + "x": registers["r" + reg[0] + "x"][:14] + hex_fill(
                (reg_value(reg) - subtracting_value) % MAX_8BIT, 2, False) + registers["r" + reg[0] + "x"][16:]})
    elif re.match(r"[abcd]l", reg, re.I):
        registers.update(
            {"r" + reg[0] + "x": registers["r" + reg[0] + "x"][:16] + hex_fill(
                (reg_value(reg) - subtracting_value) % MAX_8BIT, 2, False)})
    elif re.match(r"[a-z]{2}l", reg, re.I):
        registers.update(
            {"r" + reg[-1] + "x": registers["r" + reg[-1] + "x"][:16] + hex_fill(
                (reg_value(reg) - subtracting_value) % MAX_8BIT, 2, False)})
    elif re.match(r"r[0-9]{1,2}b", reg, re.I):
        registers.update(
            {reg[-1]: registers[reg[-1]][:16] + hex_fill(
                (reg_value(reg) - subtracting_value) % MAX_8BIT, 2, False)})

    return True


def mul(reg):
    """
    This function multiplies the value of the register "eax" by the value of another register
    :type reg: str
    :rtype: bool
    """
    global registers
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        mul_result = hex_fill(reg_value("rax") * reg_value(reg), 32)
        registers.update({"rax": "0x" + mul_result[18:],
                          "rdx": mul_result[:18]})

    # 32 bit register
    elif re.match(r"(e[a-z]{2})|(r[0-9]{1,2}d)", reg, re.I):
        mul_result = hex_fill(reg_value("eax") * reg_value(reg), 16, False)
        registers.update({"rax": registers["rax"][:10] + mul_result[8:],
                          "rdx": registers["rdx"][:10] + mul_result[:8]})

    # 16 bit register
    elif re.match(r"([a-z][xisp])|(r[0-9]{1,2}w)", reg, re.I):
        mul_result = hex_fill(reg_value("ax") * reg_value(reg), 8, False)
        registers.update({"rax": registers["rax"][:14] + mul_result[4:],
                          "rdx": registers["rdx"][:14] + mul_result[:4]})
    # 8 bit register
    elif re.match(r"([a-z]h)|([abcd]l)|([a-z]{2}l)|(r[0-9]{1,2}b)", reg, re.I):
        mul_result = hex_fill(reg_value("al") * reg_value(reg), 4, False)
        registers.update({"rax": registers["rax"][:16] + mul_result[2:],
                          "rdx": registers["rdx"][:16] + mul_result[:2]})

    return True


def imul(reg):
    """
    Like mul, but the multiplication is signed.
    :type reg: str
    :rtype: bool
    """
    global registers
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        mul_result = hex_fill(fill_to_2(fill_to_2(reg_value("rax"), MAX_64BIT, "s") *
                                        fill_to_2(reg_value(reg), MAX_64BIT, "s"), MAX_64BIT, "u"), 32)
        registers.update({"rax": "0x" + mul_result[18:],
                          "rdx": mul_result[:18]})

    # 32 bit register
    elif re.match(r"(e[a-z]{2})|(r[0-9]{1,2}d)", reg, re.I):
        mul_result = hex_fill(fill_to_2(fill_to_2(reg_value("eax"), MAX_32BIT, "s") *
                                        fill_to_2(reg_value(reg), MAX_64BIT, "s"), MAX_64BIT, "u"), 32)
        registers.update({"rax": registers["rax"][:10] + mul_result[8:],
                          "rdx": registers["rdx"][:10] + mul_result[:8]})

    # 16 bit register
    elif re.match(r"([a-z][xisp])|(r[0-9]{1,2}w)", reg, re.I):
        mul_result = hex_fill(fill_to_2(reg_value("ax") * reg_value(reg), MAX_16BIT, "s"), 8, False)
        registers.update({"rax": registers["rax"][:14] + mul_result[4:],
                          "rdx": registers["rdx"][:14] + mul_result[:4]})
    # 8 bit register
    elif re.match(r"([a-z]h)|([abcd]l)|([a-z]{2}l)|(r[0-9]{1,2}b)", reg, re.I):
        mul_result = hex_fill(reg_value("al") * reg_value(reg), 4, False)
        registers.update({"rax": registers["rax"][:16] + mul_result[2:],
                          "rdx": registers["rdx"][:16] + mul_result[:2]})

    return True


def div(reg):
    """
    This function divides the value of the register "eax" by the value of another register
    :type reg: str
    :rtype: bool
    """
    global registers
    global MAX_8BIT
    global MAX_16BIT
    global MAX_32BIT
    global MAX_64BIT

    if reg_value(reg) == 0:
        return False

    # 64 bit register
    if re.match(r"r([a-z]{2}|[0-9]{1,2})", reg, re.I):
        div_result = hex_fill(reg_value("rax") / reg_value(reg), 32)
        mod_result = hex_fill(reg_value("rax") % reg_value(reg), 32)
        registers.update({"rax": "0x" + div_result[18:],
                          "rdx": mod_result[:18]})

    # 32 bit register
    elif re.match(r"(e[a-z]{2})|(r[0-9]{1,2}d)", reg, re.I):
        div_result = hex_fill(reg_value("eax") / reg_value(reg), 16, False)
        mod_result = hex_fill(reg_value("eax") % reg_value(reg), 16, False)
        registers.update({"rax": registers["rax"][:10] + div_result[8:],
                          "rdx": registers["rdx"][:10] + mod_result[:8]})

    # 16 bit register
    elif re.match(r"([a-z][xisp])|(r[0-9]{1,2}w)", reg, re.I):
        div_result = hex_fill(reg_value("ax") / reg_value(reg), 8, False)
        mod_result = hex_fill(reg_value("ax") % reg_value(reg), 8, False)
        registers.update({"rax": registers["rax"][:14] + div_result[4:],
                          "rdx": registers["rdx"][:14] + mod_result[:4]})
    # 8 bit register
    elif re.match(r"([a-z]h)|([abcd]l)|([a-z]{2}l)|(r[0-9]{1,2}b)", reg, re.I):
        div_result = hex_fill(reg_value("al") / reg_value(reg), 4, False)
        mod_result = hex_fill(reg_value("al") % reg_value(reg), 4, False)
        registers.update({"rax": registers["rax"][:16] + div_result[2:],
                          "rdx": registers["rdx"][:16] + mod_result[:2]})

    return True


def push(reg):
    m = re.match(r"(e|r)?([a-z]{2}|[1-9]*)", reg)
    if m.group(1) == "r":
        for val in registers[reg][2:]:
            stack.append(val)
        sub("rsp", 8)
    elif m.group(1) == "e":
        for val in registers["r" + m.group(2)][10:]:
            stack.append(val)
        sub("rsp", 4)
    elif len(m.group(2)) == 2:
        if m.group(2)[1] == "x":
            for val in registers["r" + m.group(2)][14:]:
                stack.append(val)
            sub("rsp", 2)


def pop(reg):
    m = re.match(r"(e|r)?([a-z]{2}|[1-9]*)", reg)
    if m.group(1) == "r":
        registers.update({reg: "0x" + "".join(stack[-16:])})
        for i in xrange(16):
            stack.pop(-1)
        add("rsp", 8)
    elif m.group(1) == "e":
        registers.update({"r" + m.group(2): "0x" + 8*"0" + "".join(stack[-8:])})
        for i in xrange(8):
            stack.pop(-1)
        add("rsp", 4)
    elif len(m.group(2)) == 2:
        if m.group(2)[1] == "x":
            registers.update({"r" + m.group(2): "0x" + 12*"0" + "".join(stack[-4:])})
            for i in xrange(4):
                stack.pop(-1)
            add("rsp", 2)


def main(asm_file, running_time = float("inf")):
    """
    This program scanning a code in assembly.
    The program iterates every line, and checks the command. The program saves in a dictionary the value of each
    register it finds in the code. When the command is "int", the program checks the current value of the register,
    and then the program can figured out what the code does.
    :rtype: None
    """
    global registers
    global stack

    log = open("pars.log", "w")

    asm = open(asm_file, "r").read()
    asm = asm.replace(",", " ")
    asm = asm.replace(":", " ")

    # The formating of the disassembled code:
    lines = {}  # A dictionary that maps between the line numbers and the lines of the assembly code
    for line in asm.split("\n"):
        if line == "":
            continue
        if line[0].isspace() and re.match(r"([0-9A-Fa-f])*$", line.split()[0]):
            num = int(line.split()[0], 16)
            count = 0
            for i, c in enumerate(line):
                if c == "\t":
                    count += 1
                if count > 1:
                    con = line[i + 1:]
                    lines.update({num: con})
                    break

    ln = 4195542    # The analysis of the assembly code is starting from the main

    start_running = time.time()

    while ln < max(lines.keys()):

        # For some reasons, in the disassembled files of linux,
        # the line numbers aren't following each other by one exactly.
        if ln not in lines.keys():
            ln += 1
            continue
        line = lines[ln]

        # The code is running too much time
        if time.time() - start_running >= running_time:
            log.write("We are assume that the code is infinite\n")
            break

        # Comments
        if ";" in line:
            line = line[:line.index(";")]

        # Empty lines and nop command
        if line == "":
            ln += 1
            continue

        lcon = line.split()

        # "mov" command
        if "mov" in lcon[0]:
            reg1 = lcon[2][1:]
            if lcon[1][0] == "$":
                if lcon[1][1:3] == "0x":
                    mov_value = int(lcon[1][3:], 16)
                else:
                    mov_value = int(lcon[1][1:])
            elif lcon[1][0] == "%":
                reg2 = lcon[1][1:]
                mov_value = reg_value(reg2)
            elif re.match('',lcon[1]):
                    pass
            mv = mov(reg1, mov_value)
            if not mv:
                log.write("There was an error\n")
                break

        # "add" command
        elif "add" in lcon[0]:
            reg1 = lcon[2][1:]
            if lcon[1][0] == "$":
                if lcon[1][1:3] == "0x":
                    add_value = int(lcon[1][3:], 16)
                else:
                    add_value = int(lcon[1][1:])

            elif lcon[1][0] == "%":
                reg2 = lcon[1][1:]
                add_value = reg_value(reg2)
            ad = add(reg1, add_value)
            if not ad:
                log.write("There was an error\n")
                break

        # "sub" command
        elif "sub" in lcon[0]:
            reg1 = lcon[2][1:]
            if lcon[1][0] == "$":
                if lcon[1][1:3] == "0x":
                    sub_value = int(lcon[1][3:], 16)
                else:
                    sub_value = int(lcon[1][1:])

            elif lcon[1][0] == "%":
                reg2 = lcon[1][1:]
                sub_value = reg_value(reg2)
            sb = sub(reg1, sub_value)
            if not sb:
                log.write("There was an error\n")
                break

        # "inc" and "dec" commands
        elif "inc" in lcon[0]:
            add(lcon[1][1:], 1)
        elif "dec" in lcon[0]:
            sub(lcon[1][1:], 1)

        # "mul" command
        elif "mul" in lcon[0]:
            ml = mul(lcon[1][1:])
            if not ml:
                log.write("There was an error\n")
                break

        # "div" command
        elif "div" in lcon[0]:
            dv = div(lcon[1][1:])
            if not dv:
                log.write("There was an error\n")
                break

        # "push" command
        elif "push" in lcon[0]:
            push(lcon[1][1:])

        # "pop" command
        elif "pop" in lcon[0]:
            pop(lcon[1][1:])

        elif "jmp" in lcon[0]:
            if lcon[1][0] == "*":
                line_to_jmp = lcon[1][1:]
            else:
                line_to_jmp = lcon[1]
            if line_to_jmp[0].isdigit():
                ln = int(line_to_jmp, 16)
            elif line_to_jmp[0] == "%":
                ln = reg_value(line_to_jmp[1:])
            continue

        elif "loop" in lcon[0]:
            if registers["rcx"] != 0:
                if lcon[1][0] == "*":
                    line_to_jmp = lcon[1][1:]
                else:
                    line_to_jmp = lcon[1]
                if line_to_jmp[0].isdigit():
                    ln = int(line_to_jmp, 16)
                elif line_to_jmp[0] == "%":
                    ln = reg_value(line_to_jmp[1:])
                    sub(registers["rcx"], 1)
                continue

        # "syscall" command
        elif "syscall" in lcon[0]:
            sys_type = syscalls[int(registers["rax"], 16)]
            if sys_type in syscounter:
                syscounter.update({sys_type: syscounter[sys_type] + 1})
            else:
                syscounter.update({sys_type: 1})

        # The and of the code
        elif "ret" in lcon[0]:
            break

        for reg in registers.keys():
            if registers[reg][-1] == "L":
                registers.update({reg: registers[reg][:-1]})

        ln += 1

    for syscall in syscalls.values():
        if syscall not in syscounter:
            syscounter.update({syscall: 0})
    for syscall in syscounter:
        log.write(syscall + str(syscounter[syscall]) + " times.\n")
