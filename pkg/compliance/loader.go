package compliance

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// frameworkYAML is the on-disk schema for a compliance framework YAML file.
// It is used exclusively for parsing; callers work with ComplianceMapper.
type frameworkYAML struct {
	Framework   string        `yaml:"framework"`
	Version     string        `yaml:"version"`
	Description string        `yaml:"description"`
	Controls    []controlYAML `yaml:"controls"`
}

// controlYAML is the per-control entry within a framework YAML file.
type controlYAML struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	CWEs        []string `yaml:"cwes"`
}

// parseFrameworkYAML parses raw YAML bytes into a frameworkYAML struct.
func parseFrameworkYAML(data []byte) (*frameworkYAML, error) {
	var fw frameworkYAML
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return nil, fmt.Errorf("compliance: unmarshal yaml: %w", err)
	}
	if fw.Framework == "" {
		return nil, fmt.Errorf("compliance: yaml missing required 'framework' field")
	}
	return &fw, nil
}

// mapperFromFrameworkYAML constructs a ComplianceMapper from a parsed
// frameworkYAML. Currently only PCI DSS 4.0 is supported; the function
// returns a generic pciDSSMapper for any framework that starts with
// "pci-dss", and a baseMapper for everything else.
func mapperFromFrameworkYAML(fw *frameworkYAML) ComplianceMapper {
	controls := make([]Control, len(fw.Controls))
	for i, c := range fw.Controls {
		controls[i] = Control(c)
	}

	base := &baseMapper{
		framework:   fw.Framework,
		version:     fw.Version,
		description: fw.Description,
		controls:    controls,
	}
	return base
}

// LoadMapper reads a single YAML file from path and returns a ComplianceMapper.
// It returns an error if the file cannot be read or if the YAML is malformed.
func LoadMapper(path string) (ComplianceMapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("compliance: read file %q: %w", path, err)
	}
	fw, err := parseFrameworkYAML(data)
	if err != nil {
		return nil, err
	}
	return mapperFromFrameworkYAML(fw), nil
}

// LoadAllMappers reads every *.yaml file in dir and returns a ComplianceMapper
// for each. If dir does not exist or cannot be read, an error is returned.
// Files that fail to parse are skipped and their errors are aggregated.
func LoadAllMappers(dir string) ([]ComplianceMapper, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("compliance: read dir %q: %w", dir, err)
	}

	var mappers []ComplianceMapper
	var parseErrors []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
			continue
		}
		m, err := LoadMapper(filepath.Join(dir, name))
		if err != nil {
			parseErrors = append(parseErrors, err)
			continue
		}
		mappers = append(mappers, m)
	}

	if len(mappers) == 0 && len(parseErrors) > 0 {
		return nil, fmt.Errorf("compliance: all files in %q failed to parse: first error: %w", dir, parseErrors[0])
	}
	return mappers, nil
}
