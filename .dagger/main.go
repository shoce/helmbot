package main

import (
	"context"

	"dagger/helmbot/internal/dagger"

	"golang.org/x/sync/errgroup"
)

const (
	GolangDockerImage = "golang:1.23.6"
	AlpineDockerImage = "alpine:3.21.2"
	ExposedPort       = 80

	NL = "\n"
)

var (
	Platforms = []dagger.Platform{
		"linux/amd64",
		"linux/arm64",
	}
	SourceFiles = []string{
		"helmbot.go", "drlatest.go", "minio.go", "tg.go",
		"go.mod", "go.sum",
	}

	Ctx = context.TODO()
)

type Helmbot struct{}

func (m *Helmbot) Build(
	// +defaultPath="."
	srcdir *dagger.Directory,
) []*dagger.Container {

	c := make([]*dagger.Container, 0, len(Platforms))

	ff := []*dagger.File{}
	for _, fn := range SourceFiles {
		ff = append(ff, srcdir.File(fn))
	}

	eg, _ := errgroup.WithContext(Ctx)

	for _, platform := range Platforms {

		eg.Go(func() (err error) {

			// https://hub.docker.com/_/golang/tags/
			a := dag.Container(dagger.ContainerOpts{Platform: platform}).
				From(GolangDockerImage).
				WithFiles("/root/helmbot/", ff).
				WithWorkdir("/root/helmbot/").
				WithEnvVariable("CGO_ENABLED", "0").
				WithExec([]string{"go", "get", "-v"}).
				WithExec([]string{"go", "build", "-o", "helmbot", "."})

			// https://hub.docker.com/_/alpine/tags/
			b := dag.Container(dagger.ContainerOpts{Platform: platform}).
				From(AlpineDockerImage).
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
	p, _ := d.Publish(Ctx,
		registry+"/"+image,
		dagger.ContainerPublishOpts{
			PlatformVariants: m.Build(srcdir),
		},
	)

	return p

}
