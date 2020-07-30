package networkcontrol

type ServerMsg interface {
	MarshalForKambani() ([]byte, error)
}
