package networkcontrol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/FactomProject/factomd/common/constants"
	"github.com/FactomProject/factomd/common/interfaces"
	"github.com/FactomProject/factomd/common/messages"
	"github.com/FactomProject/factomd/common/messages/msgsupport"
	"github.com/FactomProject/factomd/common/primitives"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type NetworkControl struct {
	ac *AuthCache
}

const wrapper = `<!DOCTYPE html><html lang="en"><head><title>Network Control</title>
<style type="text/css">
* {
	font-family: sans-serif;
}
.ms {
	font-family: monospace;
}
td {
	padding: 2px;
}
</style>
%s
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
	e.POST("/create", nc.create)
	e.POST("/sign", nc.sign)

	return e
}

func printError(c echo.Context, err error) error {
	var out bytes.Buffer

	fmt.Fprintf(&out, wrapper, "", fmt.Sprintf("<h1>ERROR</h1>%s", err.Error()))
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

	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, "", out.String()))
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
	fmt.Fprintf(out, `<form method="post" action="/create"><table>`)
	fmt.Fprintf(out, `<tr><td colspan="2"><h1>Create New Message</h1></td></tr>`)
	fmt.Fprintf(out, `<tr><td></td><td>
		<label for="addserver"><input type="radio" name="msgtype" value="add" id="addserver"%s> Add Server</label>
		<label for="removeserver"><input type="radio" name="msgtype" value="remove" id="removeserver"%s> Remove Server</label>
	</td></tr>`, checked("add"), checked("remove"))
	fmt.Fprintf(out, `<tr><td>Chain ID</td><td><input type="text" name="chainid" size="64" value="%s"></td></tr>`, chain)
	fmt.Fprintf(out, `<tr><td>Timestamp</td><td><input type="text" name="timestamp" size="15" value="%d"></td></tr>`, ts.GetTimeMilli())
	fmt.Fprintf(out, `<tr><td></td><td>
		<label for="fedserver"><input type="radio" name="servertype" value="federated" id="fedserver"%s> Federated</label>
		<label for="auditserver"><input type="radio" name="servertype" value="audit" id="auditserver"%s> Audit</label>
	</td></tr>`, checked2("federated"), checked2("audit"))
	fmt.Fprintf(out, `<tr><td></td><td><button type="submit">Create Base Message</button></td></tr>`)
	fmt.Fprintf(out, `</table></form>`)
	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, "", out.String()))
}

func (nc *NetworkControl) create(c echo.Context) error {
	msgtype := c.FormValue("msgtype")
	chainid := c.FormValue("chainid")
	timestampString := c.FormValue("timestamp")
	timestamp, err := strconv.Atoi(timestampString)
	if err != nil {
		return printError(c, err)
	}
	servertype := c.FormValue("servertype")

	out := new(bytes.Buffer)
	if msgtype == "add" {
		out.WriteByte(constants.ADDSERVER_MSG)
	} else {
		out.WriteByte(constants.REMOVESERVER_MSG)
	}

	ts := primitives.NewTimestampFromMilliseconds(uint64(timestamp))
	tsbin, err := ts.MarshalBinary()
	if err != nil {
		return printError(c, err)
	}

	out.Write(tsbin)

	hex, err := hex.DecodeString(chainid)
	if err != nil {
		return printError(c, err)
	}
	if len(hex) != 32 {
		return errors.New("chainid not 32 bytes long")
	}

	out.Write(hex)

	if servertype == "federated" {
		out.WriteByte(0)
	} else {
		out.WriteByte(1)
	}

	return nc.printMessage(c, out.Bytes())
}

func (nc *NetworkControl) printMessage(c echo.Context, data []byte) error {

	var msg interfaces.IMsg
	var err error
	if msg, err = msgsupport.UnmarshalMessage(data); err != nil {
		return printError(c, err)
	}

	auth, err := nc.ac.Get()
	if err != nil {
		return printError(c, err)
	}

	var typ string
	var chain string
	var stype int
	var sigs, validsigs []interfaces.IFullSignature
	var payload []byte
	switch msg.Type() {
	case constants.ADDSERVER_MSG:
		add := msg.(*messages.AddServerMsg)
		chain = add.ServerChainID.String()
		typ = "Add Server"
		stype = add.ServerType
		sigs = add.GetSignatures()
		validsigs, err = add.VerifySignatures()
		if err != nil {
			return printError(c, err)
		}
		payload, err = add.MarshalForSignature()
		if err != nil {
			return printError(c, err)
		}
	case constants.REMOVESERVER_MSG:
		rem := msg.(*messages.RemoveServerMsg)
		chain = rem.ServerChainID.String()
		stype = rem.ServerType
		typ = "Remove Server"
		sigs = rem.GetSignatures()
		validsigs, err = rem.VerifySignatures()
		payload, err = rem.MarshalForSignature()
		if err != nil {
			return printError(c, err)
		}
	default:
		return printError(c, errors.New("invalid type"))
	}

	valid := make(map[string]bool)
	for _, v := range validsigs {
		key := fmt.Sprintf("%x", v.GetKey())
		valid[key] = true
	}

	var sstype string
	switch stype {
	case 0:
		sstype = "Federated"
	case 1:
		sstype = "Audit"
	default:
		return printError(c, errors.New("invalid server type"))
	}

	out := new(bytes.Buffer)
	fmt.Fprintf(out, `<table>`)
	fmt.Fprintf(out, `<tr><td colspan="2"><h1>Authset Management Message</h1></td></tr>`)
	fmt.Fprintf(out, `<tr><td><b>Raw Message</b></td><td><textarea cols="64" rows="5">%x</textarea></td></tr>`, data)
	fmt.Fprintf(out, `<tr><td><b>Msg Type</b></td><td>%s</td></tr>`, typ)
	fmt.Fprintf(out, `<tr><td><b>Time</b></td><td>%s</td></tr>`, msg.GetTimestamp().GetTime())
	fmt.Fprintf(out, `<tr><td><b>Time Relative</b></td><td>%s</td></tr>`, time.Until(msg.GetTimestamp().GetTime()))
	fmt.Fprintf(out, `<tr><td><b>Chain ID</b></td><td>%s</td></tr>`, chain)
	fmt.Fprintf(out, `<tr><td><b>Server Type</b></td><td>%s</td></tr>`, sstype)
	fmt.Fprintf(out, `</table>`)

	fmt.Fprintf(out, `<h1>Signatures</h1>`)

	if len(sigs) > 0 {
		fmt.Fprintf(out, "<table><tr><td><b>Identity Chain ID</b></td><td><b>PubKey</b></td><td><b>Valid</b></td></tr>")
		for _, s := range sigs {
			authid := "Not a valid server in the auth set"
			key := fmt.Sprintf("%x", s.GetKey())
			for _, a := range auth {
				if key == a.SigningKey {
					authid = a.AuthorityChainID
					break
				}
			}

			val := "No"
			if valid[key] {
				val = "Yes"
			}

			fmt.Fprintf(out, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", authid, key, val)
		}
		fmt.Fprintf(out, `</table>`)
	} else {
		fmt.Fprintf(out, `<div><i>None</i></div>`)
	}

	fmt.Fprintf(out, "<h1>Add Signature</h1>")
	fmt.Fprintf(out, `<form method="POST" action="/sign">`)
	fmt.Fprintf(out, `<input type="hidden" name="fullmsg" value="%x">`, data)
	fmt.Fprintf(out, `<h3>Payload to Sign</h3><textarea cols="64" rows="5">%x</textarea>`, payload)
	fmt.Fprintf(out, "<table>")
	fmt.Fprintf(out, `<tr><td>Public Key</td><td><input type="text" name="pubkey" size="32"></td></tr>`)
	fmt.Fprintf(out, `<tr><td>Signature</td><td><input type="text" name="sig" size="32"></td></tr>`)
	fmt.Fprintf(out, `<tr><td></td><td><button type="submit">Add</button></td></tr>`)
	fmt.Fprintf(out, "</table>")

	fmt.Fprintf(out, `</form>`)

	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, "", out.String()))
}

func (nc *NetworkControl) sign(c echo.Context) error {
	ffullmsg := c.FormValue("fullmsg")
	fpubkey := c.FormValue("pubkey")
	fsig := c.FormValue("sig")

	data, err := hex.DecodeString(ffullmsg)
	if err != nil {
		return printError(c, err)
	}

	pubkey, err := hex.DecodeString(fpubkey)
	if err != nil {
		return printError(c, err)
	}

	sig, err := hex.DecodeString(fsig)
	if err != nil {
		return printError(c, err)
	}

	var msg interfaces.IMsg
	if msg, err = msgsupport.UnmarshalMessage(data); err != nil {
		return printError(c, err)
	}

	signature := new(primitives.Signature)
	signature.SetPub(pubkey)
	signature.SetSignature(sig)

	switch msg.(type) {
	case *messages.AddServerMsg:
		add := msg.(*messages.AddServerMsg)
		signeddata, err := add.MarshalForSignature()
		if err != nil {
			return printError(c, err)
		}

		if !signature.Verify(signeddata) {
			return printError(c, errors.New("signature is invalid"))
		}

		add.Signatures.AddSignature(signature)
	case *messages.RemoveServerMsg:
		rem := msg.(*messages.AddServerMsg)
		signeddata, err := rem.MarshalForSignature()
		if err != nil {
			return printError(c, err)
		}

		if !signature.Verify(signeddata) {
			return printError(c, errors.New("signature is invalid"))
		}

		rem.Signatures.AddSignature(signature)
	default:
		return printError(c, fmt.Errorf("invalid message type: %d", msg.Type()))
	}

	newdata, err := msg.MarshalBinary()
	if err != nil {
		return printError(c, err)
	}

	return nc.printMessage(c, newdata)
}
