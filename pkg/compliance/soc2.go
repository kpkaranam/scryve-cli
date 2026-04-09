package compliance

import _ "embed"

//go:embed data/soc2-tsc.yaml
var soc2TSCYAML []byte

// NewSOC2Mapper constructs a ComplianceMapper for SOC 2 Trust Services Criteria
// from the embedded YAML data.
func NewSOC2Mapper() (ComplianceMapper, error) {
	fw, err := parseFrameworkYAML(soc2TSCYAML)
	if err != nil {
		return nil, err
	}
	return mapperFromFrameworkYAML(fw), nil
}
