package compliance

import _ "embed"

//go:embed data/iso27001-annexa.yaml
var iso27001AnnexAYAML []byte

// NewISO27001Mapper constructs a ComplianceMapper for ISO 27001 Annex A controls
// from the embedded YAML data.
func NewISO27001Mapper() (ComplianceMapper, error) {
	fw, err := parseFrameworkYAML(iso27001AnnexAYAML)
	if err != nil {
		return nil, err
	}
	return mapperFromFrameworkYAML(fw), nil
}
