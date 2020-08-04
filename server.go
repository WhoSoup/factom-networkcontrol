package networkcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/FactomProject/factom"
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
	padding: 4px;
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
	e.POST("/import", nc.imp)
	e.POST("/create", nc.create)
	e.POST("/sign", nc.sign)
	e.POST("/submit", nc.submit)
	e.POST("/send", nc.send)

	return e
}

func printError(c echo.Context, err error) error {
	var out bytes.Buffer

	fmt.Fprintf(&out, wrapper, "", fmt.Sprintf("<h1>ERROR</h1>%s", err.Error()))
	return c.HTMLBlob(http.StatusOK, out.Bytes())
}

func (nc *NetworkControl) imp(c echo.Context) error {
	fdata := c.FormValue("fullmsg")

	data, err := hex.DecodeString(fdata)
	if err != nil {
		return printError(c, err)
	}

	return nc.printMessage(c, data)
}

func (nc *NetworkControl) index(c echo.Context) error {
	auth, err := nc.ac.Get()
	if err != nil {
		return printError(c, err)
	}

	out := new(bytes.Buffer)

	fmt.Fprintf(out, `<h2><a href="/craft/add/new">Craft New Message</a></h2>`)

	fmt.Fprintf(out, `<h2>Import Message</h2>
	<form action="/import" method="POST">
	<table><tr><td>Message</td><td><textarea name="fullmsg" cols="60" rows="5"></textarea></td></tr><tr><td></td><td><button type="submit">Import</button></td></tr></table>
	</form>
	`)

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
			fmt.Println(action, exists.Status, s)
			if action == "remove" && exists.Status == s {
				return ` checked="checked"`
			}
			if action == "add" && exists.Status != s {
				return ` checked="checked"`
			}
		}
		return ""
	}

	ts := primitives.NewTimestampNow()
	out := new(bytes.Buffer)
	fmt.Fprintf(out, `<script type="text/javascript">
function updateTime() {
	let f = document.getElementById('ts');
	let millis = parseInt(f.value, 10);
	let date = new Date(millis);
	
	document.getElementById('tstext').innerText = date.toUTCString();
}
window.addEventListener('DOMContentLoaded', (event) => {
	updateTime();
});
</script>`)
	fmt.Fprintf(out, `<form method="post" action="/create"><table>`)
	fmt.Fprintf(out, `<tr><td colspan="2"><h1>Create New Message</h1></td></tr>`)
	fmt.Fprintf(out, `<tr><td></td><td>
		<label for="addserver"><input type="radio" name="msgtype" value="add" id="addserver"%s> Add Server</label>
		<label for="removeserver"><input type="radio" name="msgtype" value="remove" id="removeserver"%s> Remove Server</label>
	</td></tr>`, checked("add"), checked("remove"))
	fmt.Fprintf(out, `<tr><td>Chain ID</td><td><input type="text" name="chainid" size="64" value="%s"></td></tr>`, chain)
	fmt.Fprintf(out, `<tr><td>Timestamp (milliseconds)</td><td><input type="text" name="timestamp" size="15" value="%d" id="ts" onchange="updateTime()" onkeyup="updateTime()"> <span id="tstext"></span></td></tr>`, ts.GetTimeMilli())
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

	manualMsg := sha256.Sum256([]byte(fmt.Sprintf("%x", payload)))

	out := new(bytes.Buffer)
	fmt.Fprintf(out, `<script type="text/javascript">
function signWithKambani() {
	let requestID = Date.now();
	let event = new CustomEvent('SigningRequest', {
		detail: {
			"requestId": requestID,
			"requestType": "data",
			"requestInfo": {
				"data": "%x",
				"keyType": "fct",
			},
		},
	});

	window.dispatchEvent(event);
}
function toHex(bytes) {
	return Array.from(bytes, b => { return ('0'+(b & 0xff).toString(16)).slice(-2);}).join('')
}
function fromHex(s) {
	let res = [];
	for (let i = 0; i < s.length; i += 2) {
	  res.push(parseInt(s.substr(i, 2), 16));
	}
	return res;
}

window.addEventListener("SigningResponse", event => {
	console.log(event);
	console.log(toHex(event.detail.message.data));
	document.getElementById('pubkey').value = toHex(event.detail.publicKey.data);
	document.getElementById('sig').value = toHex(event.detail.signature.data);
});
</script>`, payload)
	fmt.Fprintf(out, `<form action="/submit" method="POST">`)
	fmt.Fprintf(out, `<table>`)
	fmt.Fprintf(out, `<tr><td colspan="2"><h1>Authset Management Message</h1></td></tr>`)
	fmt.Fprintf(out, `<tr><td><b>Raw Message</b></td><td><textarea cols="64" rows="5" name="fullmsg">%x</textarea></td></tr>`, data)
	fmt.Fprintf(out, `<tr><td></td><td><button type="submit">Pre-Send Checks</button></td></tr>`)
	fmt.Fprintf(out, `<tr><td><b>Msg Type</b></td><td>%s</td></tr>`, typ)
	fmt.Fprintf(out, `<tr><td><b>Time</b></td><td>%s</td></tr>`, msg.GetTimestamp().GetTime())
	fmt.Fprintf(out, `<tr><td><b>Time Relative</b></td><td>%s</td></tr>`, time.Until(msg.GetTimestamp().GetTime()))
	fmt.Fprintf(out, `<tr><td><b>Chain ID</b></td><td>%s</td></tr>`, chain)
	fmt.Fprintf(out, `<tr><td><b>Server Type</b></td><td>%s</td></tr>`, sstype)
	fmt.Fprintf(out, `</table>`)
	fmt.Fprintf(out, `</form>`)

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
	fmt.Fprintf(out, `<h3>Payload for Manual Signature</h3><textarea cols="64" rows="5">%x</textarea>`, manualMsg)
	fmt.Fprintf(out, `<div>You can sign this payload using <a href="https://github.com/FactomProject/serveridentity/tree/master/signwithed25519" target="_blank">SignWithEd25519</a></div>`)
	fmt.Fprintf(out, "<table>")
	fmt.Fprintf(out, `<tr><td></td><td><button type="button" onclick="signWithKambani()">Sign with Kambani</button></td></tr>`)
	fmt.Fprintf(out, `<tr><td>Public Key</td><td><input type="text" name="pubkey" size="32" id="pubkey"></td></tr>`)
	fmt.Fprintf(out, `<tr><td>Signature</td><td><input type="text" name="sig" size="32" id="sig"></td></tr>`)
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
		signeddata, err := add.MarshalForKambani()
		if err != nil {
			return printError(c, err)
		}

		if !signature.Verify(signeddata) {
			return printError(c, errors.New("signature is invalid"))
		}

		add.Signatures.AddSignature(signature)
	case *messages.RemoveServerMsg:
		rem := msg.(*messages.RemoveServerMsg)
		signeddata, err := rem.MarshalForKambani()
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

func (nc *NetworkControl) submit(c echo.Context) error {
	var info []string
	var errors []string
	out := new(bytes.Buffer)

	fullmsg := c.FormValue("fullmsg")
	fullmsgbytes, err := hex.DecodeString(fullmsg)
	if err != nil {
		return printError(c, err)
	}

	msg, err := msgsupport.UnmarshalMessage(fullmsgbytes)
	if err != nil {
		return printError(c, err)
	}

	ts := msg.GetTimestamp().GetTime()
	now := time.Now()
	diff := now.Sub(ts)

	if diff > time.Hour || diff < -time.Hour {
		errors = append(errors, fmt.Sprintf("The timestamp is outside the acceptable window. Must be sent between %s and %s.",
			ts.Add(-time.Hour), ts.Add(time.Hour)))
	}

	var sigs []interfaces.IFullSignature
	var server interfaces.IHash
	serverType := 0
	adding := false

	switch msg.(type) {
	case *messages.AddServerMsg:
		add := msg.(*messages.AddServerMsg)
		if s, err := add.VerifySignatures(); err != nil {
			return printError(c, err)
		} else {
			sigs = s
			server = add.ServerChainID
			serverType = add.ServerType
		}
		adding = true
	case *messages.RemoveServerMsg:
		rem := msg.(*messages.RemoveServerMsg)
		if s, err := rem.VerifySignatures(); err != nil {
			return printError(c, err)
		} else {
			sigs = s
			server = rem.ServerChainID
			serverType = rem.ServerType
		}
	default:
		return printError(c, fmt.Errorf("invalid message type: %d", msg.Type()))
	}

	auth, err := nc.ac.Get()
	if err != nil {
		return printError(c, err)
	}
	countReal := 0

	isAuth := false
	isFed := false

	for _, sig := range sigs {
		for _, a := range auth {
			if fmt.Sprintf("%x", sig.GetKey()) == a.SigningKey {
				countReal++
				break
			}
		}
	}

	for _, a := range auth {
		if server.String() == a.AuthorityChainID {
			isAuth = true
			if a.Status == "federated" {
				isFed = true
			}
			break
		}
	}

	if isAuth {
		if adding {
			if serverType == 0 { // to fed
				if isFed {
					errors = append(errors, "Promoting a node that is already a fed to fed")
				} else {
					info = append(info, "Promoting an Audit node to a Fed node and increasing # of feds")

				}
			} else if serverType == 1 { // to audit
				if isFed {
					info = append(info, "Demoting a Fed node to an Audit node and decreasing # of feds")
				} else {
					errors = append(errors, "Demoting a node that is an audit node to audit node")
				}
			}
		}
	} else { // new server
		if adding {
			typ := "Federated"
			if serverType == 1 {
				typ = "Audit"
			}
			info = append(info, fmt.Sprintf("Promoting a new server into the authority set as %s Node", typ))
		} else {
			errors = append(errors, "Trying to remove a server that's not in the authority set")
		}
	}

	if countReal < len(auth)/2+1 {
		errors = append(errors, fmt.Sprintf("There are only %d valid signatures. Need at least %d to pass", countReal, len(auth)/2+1))
	}

	fmt.Fprintf(out, "<h2>Info</h2><ul>")
	for _, i := range info {
		fmt.Fprintf(out, "<li>%s</li>", i)
	}
	fmt.Fprintf(out, "</ul>")

	fmt.Fprintf(out, "<h2>Errors</h2><ul>")
	for _, e := range errors {
		fmt.Fprintf(out, "<li>%s</li>", e)
	}

	label := "Submit to Network"
	if len(errors) > 0 {
		label = "Submit to Network despite errors"
	}
	fmt.Fprintf(out, "</ul>")
	fmt.Fprintf(out, `<form action="/send" method="POST">`)
	fmt.Fprintf(out, `<input type="hidden" name="fullmsg" value="%s">`, fullmsg)
	fmt.Fprintf(out, `<button type="submit">%s</button>`, label)
	fmt.Fprintf(out, `</form>`)

	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, "", out.String()))
}

func (nc *NetworkControl) send(c echo.Context) error {
	fullmsg := c.FormValue("fullmsg")
	fullmsgbytes, err := hex.DecodeString(fullmsg)
	if err != nil {
		return printError(c, err)
	}

	_, err = msgsupport.UnmarshalMessage(fullmsgbytes)
	if err != nil {
		return printError(c, err)
	}

	factom.SendRawMsg(fullmsg)
	return c.HTML(http.StatusOK, fmt.Sprintf(wrapper, "", "Message submitted. <a href=\"/\">Go back</a>"))
}
