package security

const (
	ActionAllow = "allow"
	ActionWarn  = "warn"
	ActionMask  = "mask"
	ActionBlock = "block"
)

type Text struct {
	Path     string
	Value    string
	Maskable bool
}

type Payload struct {
	Root  any
	Texts []Text
}

type Match struct {
	RuleID   string
	Category string
	Path     string
	Start    int
	End      int
	Original string
	Keyword  string
	Target   string
	Action   string
	Maskable bool
}

type Decision struct {
	Action  string
	Matches []Match
}

func actionPriority(action string) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionMask:
		return 3
	case ActionWarn:
		return 2
	default:
		return 1
	}
}
