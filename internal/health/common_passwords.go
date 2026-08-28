package health

// commonPasswordList is a small built-in dictionary of the most frequently
// leaked/reused passwords (compiled from widely published breach-analysis
// top-lists). Any vault entry whose password matches one of these
// case-insensitively is flagged CRITICAL. This is intentionally embedded
// in code rather than loaded from a file, per the feature spec.
var commonPasswordList = []string{
	"password", "123456", "12345678", "123456789", "qwerty", "abc123",
	"monkey", "master", "dragon", "login", "admin", "letmein", "welcome",
	"shadow", "sunshine", "trustno1", "iloveyou", "batman", "access",
	"hello", "charlie", "donald", "football", "michael", "ninja",
	"mustang", "password1", "1234567", "12345", "1234567890", "qwerty123",
	"1q2w3e4r", "111111", "1234", "123123", "000000", "iloveyou1",
	"1qaz2wsx", "qwertyuiop", "admin123", "root", "toor", "pass",
	"passw0rd", "starwars", "freedom", "whatever", "qazwsx", "trustno1",
	"jordan23", "harley", "ranger", "hunter", "buster", "soccer",
	"hockey", "killer", "george", "sexy", "andrew", "tigger",
	"baseball", "computer", "abcd1234", "michelle", "jessica", "pepper",
	"1111", "zxcvbnm", "555555", "11111111", "131313", "121212",
	"princess", "flower", "cheese", "asdfgh", "iloveu", "amanda",
	"summer", "winter", "spring", "autumn", "matrix", "orange",
	"purple", "yellow", "chicken", "banana", "apple123", "superman",
	"batman1", "spiderman", "letmein1", "welcome1", "monkey123",
	"dragon123", "shadow1", "mustang1", "football1", "baseball1",
	"jennifer", "hannah", "thomas", "robert", "daniel", "nicole",
	"anthony", "cookie", "secret", "internet",
}

// commonPasswordSet mirrors commonPasswordList as a set for O(1) lookups,
// built once at package init.
var commonPasswordSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(commonPasswordList))
	for _, p := range commonPasswordList {
		set[p] = struct{}{}
	}
	return set
}()
