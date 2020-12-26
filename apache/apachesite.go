package apache

// Site implements functionality for site enabling/disabling
type Site struct {
	DissitePath, EnsitePath string
}

// Enable enables site via a2ensite utility
func (s *Site) Enable(siteCongName string) error {
	return nil
}

// Disable disables site via a2dissite utility
func (s *Site) Disable(siteCongName string) error {
	return nil
}
