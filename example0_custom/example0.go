package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"fmt"
	"os"
	"os/signal"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// creating a channel and whenever a interrupt signal is received notifying that channel
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt) // notifying for interrupt signal

	b, err := bpf.NewModuleFromFile("example0.bpf.o")
	must(err)       // checking if there is an error
	defer b.Close() // on exit from whatever the function we are in this code is executed

	must(b.BPFLoadObject())

	p, err := b.GetProgram("socket_created")
	must(err)

	_, err = p.AttachKprobe("__x64_sys_socket")
	must(err)

	// printing from the
	go bpf.TracePrint()

	// we are blocking on the inturrupt to here
	<-sig
	fmt.Println("Cleaning....") // to know when we are exiting
}
