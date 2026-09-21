package traefik_http_knock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Traefik loads local plugins with the Yaegi interpreter, which is not a
// complete Go implementation. The tests in this file keep the plugin inside the
// subset that Yaegi can run, so a regression is caught by `go test` instead of
// by a panic in production.

// pluginSourceFiles returns the non-test Go files of the plugin package.
func pluginSourceFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot list the package directory: %v", err)
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		t.Fatal("no plugin source files found")
	}
	return files
}

// TestPluginImportsStandardLibraryOnly enforces the "no third-party dependency"
// promise: Yaegi must be able to resolve every import inside the Traefik image.
func TestPluginImportsStandardLibraryOnly(t *testing.T) {
	fset := token.NewFileSet()

	for _, file := range pluginSourceFiles(t) {
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", file, err)
			}
			first := path
			if i := strings.IndexByte(path, '/'); i >= 0 {
				first = path[:i]
			}
			// Standard library import paths never contain a dot in their first
			// segment; third-party and module paths always do.
			if strings.Contains(first, ".") {
				t.Errorf("%s imports %q: the plugin must depend on the standard library only", file, path)
			}
		}
	}
}

// TestPluginAvoidsYaegiUnsupportedCalls guards against the stdlib helpers that
// Yaegi v0.16 (shipped with Traefik v3.2) cannot run.
//
// errors.Is/errors.As/errors.Unwrap panic inside the interpreter with
// "*target must be interface or implement error", which Traefik turns into a
// 500 after recovering. Error classification must therefore use direct type
// assertions on unwrapped errors.
func TestPluginAvoidsYaegiUnsupportedCalls(t *testing.T) {
	forbidden := []string{
		"errors.Is(",
		"errors.As(",
		"errors.Unwrap(",
		"unsafe.",
		"//go:embed",
	}

	fset := token.NewFileSet()
	for _, file := range pluginSourceFiles(t) {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		content := string(src)

		for _, needle := range forbidden {
			if strings.Contains(content, needle) {
				t.Errorf("%s uses %q, which Yaegi cannot execute; use a direct type assertion on an unwrapped error instead", file, needle)
			}
		}

		// Re-parse as a sanity check that the file stays valid Go.
		if _, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
	}
}

// TestPluginExportsTraefikEntryPoints documents the plugin contract Traefik
// relies on: an exported Config type, CreateConfig() and New() with the v3
// signature. The compiler enforces most of it; the AST check keeps the package
// from accidentally renaming an entry point.
func TestPluginExportsTraefikEntryPoints(t *testing.T) {
	fset := token.NewFileSet()
	var (
		foundConfig       bool
		foundCreateConfig bool
		foundNew          bool
	)

	for _, file := range pluginSourceFiles(t) {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Recv != nil {
				continue
			}
			switch fn.Name.Name {
			case "CreateConfig":
				foundCreateConfig = true
			case "New":
				foundNew = true
			}
		}
		if structType, ok := typeConfig(parsed); ok {
			t.Logf("%s declares Config with %d fields", file, len(structType.Fields.List))
			foundConfig = true
		}
	}

	if !foundConfig {
		t.Error("the package must export a Config type")
	}
	if !foundCreateConfig {
		t.Error("the package must export CreateConfig() *Config")
	}
	if !foundNew {
		t.Error("the package must export New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)")
	}
}

// TestYaegiCompatAvoidsMultiExpressionCases forbids comma-separated case lists
// such as
//
//	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
//
// Yaegi v0.16.1 (shipped with Traefik v3.7) evaluates only the *first*
// expression of such a list instead of OR-ing the entries, so the remaining
// expressions are dead code. Real Go honours all of them, which makes this bug
// invisible to `go test`: it only shows up when the plugin runs in Traefik.
//
// Write one expression per case clause instead; the extra clauses are free.
func TestYaegiCompatAvoidsMultiExpressionCases(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range pluginSourceFiles(t) {
		parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok || len(clause.List) < 2 {
				return true
			}
			position := fset.Position(clause.Pos())
			t.Errorf("%s:%d: case clause lists %d expressions; Yaegi evaluates only the first one, so use one case clause per expression",
				file, position.Line, len(clause.List))
			return true
		})
	}
}

func typeConfig(file *ast.File) (*ast.StructType, bool) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Config" {
				continue
			}
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				return structType, true
			}
		}
	}
	return nil, false
}
