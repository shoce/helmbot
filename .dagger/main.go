package main

import (
	"context"

	"dagger/helmbot/internal/dagger"
)

const (
	NL = "\n"
)

var (
	Ctx = context.TODO()
)

type Helmbot struct{}

func (m *Helmbot) Build(
	// +defaultPath="."
	srcdir *dagger.Directory,
) []*dagger.Container {

	var Platforms = []dagger.Platform{
		"linux/amd64",
		"linux/arm64",
	}
	c := make([]*dagger.Container, 0, len(Platforms))

	fnn := []string{
		"helmbot.go", "drlatest.go", "minio.go", "tg.go",
		"go.mod", "go.sum",
	}
	ff := []*dagger.File{}
	for _, fn := range fnn {
		ff = append(ff, srcdir.File(fn))
	}

	for _, platform := range Platforms {

		/*
			arch, err := dag.Containerd().ArchitectureOf(Ctx, platform)
			if err != nil {
				return nil
			}
		*/

		// https://hub.docker.com/_/golang/tags/
		a := dag.Container(dagger.ContainerOpts{Platform: platform}).
			From("golang:1.23.6").
			WithFiles("/root/helmbot/", ff).
			WithWorkdir("/root/helmbot/").
			WithEnvVariable("CGO_ENABLED", "0").
			WithExec([]string{"go", "get", "-v"}).
			WithExec([]string{"go", "build", "-o", "helmbot", "."})

		// https://hub.docker.com/_/alpine/tags/
		b := dag.Container(dagger.ContainerOpts{Platform: platform}).
			From("alpine:3.21.2").
			WithExec([]string{"apk", "add", "--no-cache", "gcompat"}).
			WithExec([]string{"ln", "-s", "-f", "-v", "ld-linux-x86-64.so.2", "/lib/libresolv.so.2"}).
			WithFile("/bin/helmbot", a.File("/root/helmbot/helmbot")).
			WithWorkdir("/root/").
			WithEntrypoint([]string{"/bin/helmbot"}).
			WithExposedPort(80)

		/*
			p, _ := b.Platform(Ctx)
			fmt.Printf("platform==%s arch==%s"+NL, p, arch)
		*/
		c = append(c, b)

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
