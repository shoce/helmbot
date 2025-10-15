package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/helmbot/internal/dagger"

	"golang.org/x/sync/errgroup"
)

const (
	// https://hub.docker.com/_/golang/tags
	GolangDockerImage = "golang:1.25-alpine3.22"

	// https://hub.docker.com/_/alpine/tags/
	AlpineDockerImage = "alpine:3.22"

	ExposedPort = 80

	NL = "\n"
)

var (
	Platforms = []dagger.Platform{
		"linux/arm64",
		"linux/amd64",
	}
	SourceFiles = []string{
		"helmbot.go", "go.mod", "go.sum",
	}

	Ctx = context.TODO()
)

type Helmbot struct{}

func (m *Helmbot) Build(
	// +defaultPath="."
	srcdir *dagger.Directory,
	// +optional
	version string,
) []*dagger.Container {

	c := make([]*dagger.Container, 0, len(Platforms))

	ff := []*dagger.File{}
	for _, fn := range SourceFiles {
		ff = append(ff, srcdir.File(fn))
	}

	eg, _ := errgroup.WithContext(Ctx)

	for _, platform := range Platforms {

		eg.Go(func() (err error) {

			GOARCH := strings.Split(string(platform), "/")[1]
			VERSION := version
			fmt.Printf("platform %s"+NL, platform)
			fmt.Printf("GOARCH %s"+NL, GOARCH)
			fmt.Printf("VERSION %s"+NL, VERSION)

			a := dag.Container().
				From(GolangDockerImage).
				WithFiles("/root/helmbot/", ff).
				WithWorkdir("/root/helmbot/").
				WithEnvVariable("CGO_ENABLED", "0").
				WithEnvVariable("GOARCH", GOARCH).
				WithExec([]string{"go", "get", "-v"}).
				WithExec([]string{"go", "build", "-o", "helmbot", "-ldflags", "-X main.VERSION=" + VERSION, "."})

			b := dag.Container(dagger.ContainerOpts{Platform: platform}).
				From(AlpineDockerImage).
				WithExec([]string{"apk", "upgrade", "--no-cache"}).
				WithExec([]string{"apk", "add", "--no-cache", "gcompat"}).
				WithExec([]string{"ln", "-s", "-f", "-v", "ld-linux-x86-64.so.2", "/lib/libresolv.so.2"}).
				WithFile("/bin/helmbot", a.File("/root/helmbot/helmbot")).
				WithWorkdir("/root/").
				WithEntrypoint([]string{"/bin/helmbot"}).
				WithExposedPort(ExposedPort)

			c = append(c, b)

			return err
		})

		eg.Wait()

	}

	return c

}

func (m *Helmbot) Publish(
	// +defaultPath="."
	srcdir *dagger.Directory,
	// +optional
	version string,
	// +default="ghcr.io"
	registry string,
	// +optional
	username string,
	// +optional
	password *dagger.Secret,
	image string,
) string {

	d := dag.Container()
	if username != "" {
		d = d.WithRegistryAuth(registry, username, password)
	}
	p, _ := d.Publish(
		Ctx,
		registry+"/"+image,
		dagger.ContainerPublishOpts{
			PlatformVariants: m.Build(srcdir, version),
		},
	)

	return p

}
