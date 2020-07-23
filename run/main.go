package main

import (
	"context"

	"github.com/FactomProject/factom"
	networkcontrol "github.com/WhoSoup/factom-networkcontrol"
	"github.com/labstack/gommon/log"
)

func main() {
	factom.SetFactomdServer("https://api.factomd.net")
	srv := networkcontrol.CreateServer()
	defer srv.Shutdown(context.Background())
	log.Fatal(srv.Start(":8091"))
}
