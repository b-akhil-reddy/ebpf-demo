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
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("example2.bpf.o")
	must(err)
	defer b.Close()

	must(b.BPFLoadObject())

	p, err := b.GetProgram("send_command_name")
	must(err)

	_, err = p.AttachKprobe("__x64_sys_socket")
	must(err)

	e := make(chan []byte, 300)
	pb, err := b.InitPerfBuf("datastore", e, nil, 1024)
	must(err)
	pb.Start()
	c := make(map[string]int, 1000)
	go func() {
		for {
			data := <-e
			comm := string(data)
			c[comm]++
		}
	}()

	<-sig
	fmt.Println("Cleaning....")
	pb.Stop()
	for comm, n := range c {
		fmt.Printf("%s: %d\n", comm, n)
	}
}
