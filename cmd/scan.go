package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/pipeline"
	"github.com/scryve/scryve/pkg/report"
	"github.com/scryve/scryve/pkg/toolmanager"

	// Import adapters to trigger init() registration
	_ "github.com/scryve/scryve/pkg/email"
)

// scanFlags holds flags specific to the scan subcommand.
type scanFlags struct {
	compliance  string
	output      string
	format      string
	autoInstall bool
}

var scanOpts scanFlags

// MissingToolsMessage returns a human-readable advisory message listing the
// tools that are absent and suggesting how to install them.
// Exported so tests and other packages can use it without reimplementing the
// formatting logic.
func MissingToolsMessage(names []string) string {
	return fmt.Sprintf(
		"Missing tools: %s\nRun 'scryve setup' to install them automatically.",
		strings.Join(names, ", "),
	)
}

// scanCmd implements `scryve scan <domain>`.
var scanCmd = &cobra.Command{
	Use:   "scan <domain>",
	Short: "Scan a domain and produce a security report",
	Long: `Scan accepts a single domain name and runs the full Scryve pipeline:

  1. Email security checks  — SPF / DKIM / DMARC DNS validation
  2. Subfinder              — passive subdomain enumeration
  3. httpx                  — HTTP probing and technology detection
  4. Naabu                  — port scanning
  5. Nuclei                 — vulnerability scanning

Findings are normalised, optionally mapped to a compliance framework,
and written to a structured report.

Examples:
  scryve scan example.com
  scryve scan example.com --compliance pci-dss-4.0
  scryve scan example.com --output report.html --format html
  scryve scan example.com --output report.json --format json`,

	Args: cobra.ExactArgs(1),

	RunE: func(cmd *cobra.Command, args []string) error {
		domain := strings.TrimSpace(args[0])
		if domain == "" {
			return fmt.Errorf("domain must not be empty")
		}

		// Validate output format.
		validFormats := map[string]bool{"html": true, "json": true, "both": true}
		if scanOpts.format != "" && !validFormats[scanOpts.format] {
			return fmt.Errorf("unsupported format %q: must be one of html, json, both", scanOpts.format)
		}

		// Infer format from output file extension when --format is not set.
		if scanOpts.format == "" && scanOpts.output != "" {
			switch {
			case strings.HasSuffix(scanOpts.output, ".json"):
				scanOpts.format = "json"
			default:
				scanOpts.format = "html"
			}
		}
		if scanOpts.format == "" {
			scanOpts.format = "html"
		}

		// ----------------------------------------------------------------
		// Tool availability check — advisory (never blocks the scan).
		// ----------------------------------------------------------------
		toolMgr := toolmanager.NewManager()
		toolMgr.Verbose = cfg.Verbose

		// Ensure managed bin dir is in PATH for this process.
		_ = toolMgr.EnsurePath()

		_, missingTools, _ := toolMgr.CheckAll()
		if len(missingTools) > 0 {
			missingNames := make([]string, 0, len(missingTools))
			for _, t := range missingTools {
				missingNames = append(missingNames, t.Name)
			}

			if scanOpts.autoInstall {
				fmt.Fprintf(os.Stderr, "Installing missing tools: %s\n", strings.Join(missingNames, ", "))
				if err := toolMgr.InstallAll(os.Stderr); err != nil {
					fmt.Fprintf(os.Stderr, "warning: auto-install failed: %v\n", err)
				}
			} else {
				fmt.Fprintln(os.Stderr, MissingToolsMessage(missingNames))
			}
		}

		// Print startup banner so the user knows the scan is running.
		fmt.Fprintf(os.Stdout, "Scryve — scanning %s\n", domain)
		if scanOpts.compliance != "" {
			fmt.Fprintf(os.Stdout, "Compliance framework: %s\n", scanOpts.compliance)
		}
		fmt.Fprintf(os.Stdout, "Output format: %s\n", scanOpts.format)
		if scanOpts.output != "" {
			fmt.Fprintf(os.Stdout, "Output file: %s\n", scanOpts.output)
		}
		if cfg.Verbose {
			fmt.Fprintf(os.Stdout, "Rate limit: %d req/s | OutputDir: %s\n", cfg.RateLimit, cfg.OutputDir)
		}

		// ----------------------------------------------------------------
		// Pipeline execution
		// ----------------------------------------------------------------
		pipelineCfg := pipeline.PipelineConfig{
			RateLimit: cfg.RateLimit,
			OutputDir: cfg.OutputDir,
			Verbose:   cfg.Verbose,
		}
		reg := adapter.GetGlobalRegistry()
		p := pipeline.New(reg, pipelineCfg, pipeline.DefaultStages())
		pipelineResult, pipelineErr := p.Run(cmd.Context(), domain, os.Stdout)
		if pipelineErr != nil {
			return fmt.Errorf("scan failed: %w", pipelineErr)
		}

		// ----------------------------------------------------------------
		// Compliance mapping
		// ----------------------------------------------------------------
		var reporter report.ComplianceReporter
		if scanOpts.compliance != "" {
			mapper, mapErr := resolveComplianceMapper(scanOpts.compliance)
			if mapErr != nil {
				fmt.Fprintf(os.Stderr, "warning: compliance mapper unavailable: %v\n", mapErr)
			} else {
				reporter = report.NewComplianceReporter(mapper)
			}
		}

		// ----------------------------------------------------------------
		// Report generation
		// ----------------------------------------------------------------
		summary := report.SummarizeFindings(pipelineResult.Findings)
		grade := report.CalculateGrade(summary)
		fmt.Fprintf(os.Stdout, "\nSecurity Grade: %s | Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
			grade, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info)

		return generateAndWriteReport(pipelineResult, reporter, scanOpts.format, scanOpts.output)
	},
}

// resolveComplianceMapper returns the ComplianceMapper for the given framework
// name. Currently only PCI DSS 4.0 is built in.
func resolveComplianceMapper(framework string) (compliance.ComplianceMapper, error) {
	lower := strings.ToLower(strings.TrimSpace(framework))
	switch {
	case strings.HasPrefix(lower, "pci-dss"):
		return compliance.NewPCIDSSMapper()
	default:
		return nil, fmt.Errorf("unknown compliance framework %q; supported values: pci-dss-4.0", framework)
	}
}

// generateAndWriteReport produces the requested report format(s) and writes
// them to path (or stdout when path is empty).
func generateAndWriteReport(
	pipelineResult *pipeline.PipelineResult,
	reporter report.ComplianceReporter,
	format string,
	outputPath string,
) error {
	switch format {
	case "json":
		return writeJSON(pipelineResult, reporter, outputPath)
	case "both":
		htmlPath := outputPath
		jsonPath := outputPath
		if !strings.HasSuffix(htmlPath, ".html") {
			htmlPath = outputPath + ".html"
		}
		if !strings.HasSuffix(jsonPath, ".json") {
			jsonPath = outputPath + ".json"
		}
		if err := writeHTML(pipelineResult, reporter, htmlPath); err != nil {
			return err
		}
		return writeJSON(pipelineResult, reporter, jsonPath)
	default: // "html"
		return writeHTML(pipelineResult, reporter, outputPath)
	}
}

// writeJSON marshals a JSON report and writes it to path (or stdout).
func writeJSON(result *pipeline.PipelineResult, reporter report.ComplianceReporter, path string) error {
	data, err := report.GenerateJSON(result, reporter)
	if err != nil {
		return fmt.Errorf("report: JSON generation failed: %w", err)
	}
	if path == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("report: write JSON to %q: %w", path, err)
	}
	fmt.Fprintf(os.Stdout, "JSON report written to %s\n", path)
	return nil
}

// writeHTML renders an HTML report and writes it to path (or stdout).
func writeHTML(result *pipeline.PipelineResult, reporter report.ComplianceReporter, path string) error {
	data, err := report.GenerateHTML(result, reporter)
	if err != nil {
		return fmt.Errorf("report: HTML generation failed: %w", err)
	}
	if path == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("report: write HTML to %q: %w", path, err)
	}
	fmt.Fprintf(os.Stdout, "HTML report written to %s\n", path)
	return nil
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(
		&scanOpts.compliance, "compliance", "",
		"compliance framework to map findings to (e.g. pci-dss-4.0)",
	)
	scanCmd.Flags().StringVarP(
		&scanOpts.output, "output", "o", "",
		"output file path for the report (e.g. report.html, report.json)",
	)
	scanCmd.Flags().StringVar(
		&scanOpts.format, "format", "",
		"report format: html | json | both (inferred from --output extension when omitted)",
	)
	scanCmd.Flags().BoolVar(
		&scanOpts.autoInstall, "auto-install", false,
		"automatically install any missing tools before running the scan",
	)
}
