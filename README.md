# ebpf-demo
Repository to understand how to write eBPF programs in restricted C and load them into the kernel.

# Installation
- Each of the examples has a package.sh file which has the required packages that should be installed to run the ebpf programs
- Use the go documentation to install [golang](https://go.dev/doc/install)

# Running the programs
- Each example has a makefile associated with that example just running make command would create an executable and object code
- Once the executable is created use the following command
  ```bash
  sudo ./<name_of_executable>
  ```
- eBPF programs require a privileged context because of which previlege escalation is required
