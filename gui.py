#!/usr/bin/python

from Tkinter import *
import threading
import asm_scanner
import os
import sys


def time_parsing(inp_time):
    if inp_time == "":
        return float("inf")
    time_units = inp_time.split(":")
    if len(time_units) < 3:
        time_in_seconds = 0
        for unit, t in enumerate(time_units[::-1]):
            time_in_seconds += float(t) * (60 ** unit)
        return time_in_seconds
    else:
        raise ValueError("Must be at most 3 time units ({} given)".format(len(time_units)))


def button_action():
    """
    This function is a command for the button "decode_button"
    :rtype: None
    """
    global path_entry
    global time_entry
    global infinity_run_agree
    global massage

    path = path_entry.get()
    running_time = time_parsing(time_entry.get())

    os.system("objdump -d {} > disassembled_elf.txt".format(path))

    top = Toplevel()
    top.title(path + " - log")
    top.geometry("400x600")

    load = Label(top, text="loading...", font=("Times New Roman", 72))
    load.pack(expand=True)

    asm_scanner.main("disassembled_elf.txt", running_time)  # Change this line to use our code on the given path
    log = open("pars.log", "r").read()
    load.destroy()

    top_label = Label(top, text=log, font=("Times New Roman", 14), justify=LEFT)
    top_label.grid()

    while top.state() == "normal":
        pass


def thred():
    t1 = threading.Thread(target=button_action)
    t1.start()


def main():
    """

    :return:
    """
    global path_entry
    global time_entry

    root = Tk()  # Opens the window

    root.title("Error 404 - Name Not Found")  # Our team name
    root.geometry("400x300")

    path_label = Label(root, text="Enter .elf file path here:", font=("Times New Roman", 14))
    path_label.grid(row=0)

    path_entry = Entry(root, font=("Times New Roman", 14))
    path_entry.grid(row=0, column=1)

    time_label = Label(root, text="Enter the running time here:", font=("Times New Roman", 14))
    time_label.grid(row=1)

    time_entry = Entry(root, font=("Times New Roman", 14))
    time_entry.grid(row=1, column=1)

    decode_button = Button(root, text="Scan", command=thred, font=("Times New Roman", 18))
    decode_button.grid(row=2, columnspan=2)

    root.mainloop()


if __name__ == '__main__':
    main()
    sys.exit()
