package detect

import "strings"

// Base images used by the built-in templates. They are pinned by tag here;
// release builds pin them by digest via builders/images.lock (SC-19) and the
// node can redirect Docker Hub images to a mirror with ImagePrefix.
var baseImages = map[string]string{
	"node":          "node:%s-bookworm-slim",
	"bun":           "oven/bun:1-slim",
	"python":        "python:%s-slim-bookworm",
	"golang":        "golang:%s-bookworm",
	"go-runtime":    "gcr.io/distroless/static-debian12:nonroot",
	"maven":         "maven:3.9-eclipse-temurin-%s",
	"gradle":        "gradle:8-jdk%s",
	"jre":           "eclipse-temurin:%s-jre",
	"dotnet-sdk":    "mcr.microsoft.com/dotnet/sdk:%s",
	"dotnet-aspnet": "mcr.microsoft.com/dotnet/aspnet:%s",
	"ruby":          "ruby:%s-slim-bookworm",
	"composer":      "composer:2",
	"php":           "php:%s-apache-bookworm",
	"rust":          "rust:%s-slim-bookworm",
	"debian":        "debian:bookworm-slim",
	"elixir":        "elixir:%s-slim",
}

// Digests optionally pins images (filled from builders/images.lock at
// release time). Key is the fully expanded tag reference.
var Digests = map[string]string{}

func image(prefix, key, version string) string {
	tmpl := baseImages[key]
	ref := tmpl
	if strings.Contains(tmpl, "%s") {
		ref = strings.Replace(tmpl, "%s", version, 1)
	}
	if d, ok := Digests[ref]; ok {
		ref = ref + "@" + d
	}
	return withPrefix(prefix, ref)
}

// withPrefix rewrites Docker Hub references to a mirror prefix.
func withPrefix(prefix, ref string) string {
	if prefix == "" {
		return ref
	}
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") && parts[0] != "docker.io" {
		return ref // non-Docker-Hub registry
	}
	ref = strings.TrimPrefix(ref, "docker.io/")
	if !strings.Contains(ref, "/") {
		ref = "library/" + ref
	}
	return strings.TrimRight(prefix, "/") + "/" + ref
}
