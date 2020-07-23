package networkcontrol

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type NetworkControl struct {
	ac *AuthCache
}

const wrapper = `<!DOCTYPE html><html lang="en"><head><title>Network Control</title>
<style type="text/css">
.ms {
	font-family: monospace;
}
</style>
</head><body>%s</body></html>`

func CreateServer() *echo.Echo {
	nc := new(NetworkControl)
	nc.ac = NewAuthCache(time.Minute)

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/create/:action/:chainid", nc.create)
	e.GET("/", nc.index)

	return e
}

func printError(c echo.Context, err error) error {
	var out bytes.Buffer

	fmt.Fprintf(&out, wrapper, fmt.Sprintf("<h1>ERROR</h1>%s", err.Error()))
	return c.HTMLBlob(http.StatusOK, out.Bytes())
}

func (nc *NetworkControl) index(c echo.Context) error {
	auth, err := nc.ac.Get()
	if err != nil {
		return printError(c, err)
	}

	out := new(bytes.Buffer)

	fmt.Fprintf(out, "<h2>Authorities</h2><table><tr><td><b>Identity Chain ID</b></td><td><b>PubKey</b></td><td><b>Status</b></td><td colspan=\"2\"></td></tr>")
	for _, a := range auth {
		fmt.Fprintf(out, fmt.Sprintf(`<tr><td class="ms">%s</td><td class="ms">%s</td><td>%s</td><td><a href="/create/add/%[1]s">Promote</a></td><td><a href="/create/remove/%[1]s">Remove</a></td></tr>`, a.AuthorityChainID, a.SigningKey, a.Status))
	}
	fmt.Fprintf(out, "</table>")

	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, out.String()))
}

func (nc *NetworkControl) create(c echo.Context) error {
	return printError(c, errors.New("test"))
}
