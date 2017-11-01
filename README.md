# README #

### What is this repository for? ###

* This repository is a repository of the project "File Detector" of "Error 404 - Name Not Found".
* The project goal is to know if an executable file (ELF) is touching any other files, and maby does suspicius things.
* The program disassembling the ELF file to an assembly code, and then scanning the assembly code to find syscalls that trying to do stuff with files.

### Instructions ###

* Run the GUI named "gui.py".
* Enter the path of the ELF file you want to check.
* Enter the maximum time the program will run. You can leave the entry empty, but if the ELF file execute is infinite, the program will run forever (or until you stop it).
  The time syntax: [[hours:]minutes:]seconds
* Press the Scan button.

### Version ###
* Version 2017
* Intended for 64-bit computers

### Credits ###

* The project was programed by the team "Error 404 - Name Not Found".
* The team members are: Roey Samburski, Eyal Nesher and Nir Shahar.
