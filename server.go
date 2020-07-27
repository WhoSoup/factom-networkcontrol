package networkcontrol

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/FactomProject/factomd/common/primitives"
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

	e.GET("/craft/:action/:chainid", nc.craft)
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
		pd := "Promote"
		if a.Status == "federated" {
			pd = "Demote"
		}
		fmt.Fprintf(out, fmt.Sprintf(`<tr><td class="ms">%s</td><td class="ms">%s</td><td>%s</td><td><a href="/craft/add/%[1]s">%[4]s</a></td><td><a href="/craft/remove/%[1]s">Remove</a></td></tr>`, a.AuthorityChainID, a.SigningKey, a.Status, pd))
	}
	fmt.Fprintf(out, "</table>")

	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, out.String()))
}

var isHex = regexp.MustCompile("^[a-fA-F0-9]{64}$")

func (nc *NetworkControl) craft(c echo.Context) error {
	action := c.Param("action")
	chain := c.Param("chainid")
	if chain == "new" {
		chain = ""
	} else if len(chain) != 64 || !isHex.Match([]byte(chain)) {
		return printError(c, errors.New("chain must be 32 bytes hex"))
	}

	checked := func(s string) string {
		if action == s {
			return ` checked="checked"`
		}
		return ""
	}

	exists, err := nc.ac.GetSpecific(chain)
	if err != nil {
		return printError(c, err)
	}

	checked2 := func(s string) string {
		if exists != nil {
			if action == "remove" && exists.Status == s {
				return ` checked="checked"`
			} else if exists.Status != s {
				return ` checked="checked"`
			}
		}
		return ""
	}

	ts := primitives.NewTimestampNow()
	out := new(bytes.Buffer)
	fmt.Fprintf(out, `<form method="POST" action=""><table>`)
	fmt.Fprintf(out, `<tr><td colspan="2">Create New Message</td></tr>`)
	fmt.Fprintf(out, `<tr><td colspan="2">
		<label for="addserver"><input type="radio" name="msgtype" value="add" id="addserver"%s> Add Server</label>
		<label for="removeserver"><input type="radio" name="msgtype" value="remove" id="removeserver"%s> Remove Server</label>
	</td></tr>`, checked("add"), checked("remove"))
	fmt.Fprintf(out, `<tr><td>Chain ID</td><td><input type="text" name="chainid" size="64" value="%s"></td></tr>`, chain)
	fmt.Fprintf(out, `<tr><td>Timestamp</td><td><input type="text" name="timestamp" size="15" value="%d"></td></tr>`, ts.GetTimeMilli())
	fmt.Fprintf(out, `<tr><td colspan="2">
		<label for="fedserver"><input type="radio" name="servertype" value="add" id="fedserver"%s> Federated</label>
		<label for="auditserver"><input type="radio" name="servertype" value="remove" id="auditserver"%s> Audit</label>
	</td></tr>`, checked2("federated"), checked2("audit"))
	fmt.Fprintf(out, `<tr><td colspan="2"><button type="submit">Create Base</button></td></tr>`)
	fmt.Fprintf(out, `</table></form>`)
	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, out.String()))
}

func (nc *NetworkControl) printMessage(c echo.Context, data []byte) error {
	out := new(bytes.Buffer)
	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, out.String()))
}
