package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/FactomProject/factom"
	networkcontrol "github.com/WhoSoup/factom-networkcontrol"
)

func main() {
	factomd := flag.String("f", "https://api.factomd.net", "Specify the API endpoint to use")
	flag.Parse()
	factom.SetFactomdServer(*factomd)
	fmt.Println("Using API:", *factomd)

	heights, err := factom.GetHeights()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Using network at height:", heights.DirectoryBlockHeight)

	srv := networkcontrol.CreateServer()
	defer srv.Shutdown(context.Background())
	log.Fatal(srv.Start(":8091"))
}
