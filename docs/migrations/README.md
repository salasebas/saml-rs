# How to upgrade saml-rs

Apply the guides in order, starting with your installed minor version. Each
guide covers one upgrade. The [changelog](../../CHANGELOG.md) lists compatible
additions.

## Guides

- [How to upgrade from 0.2 to 0.3](0.2.x-to-0.3.0/README.md)
- [How to upgrade from 0.3 to 0.4](0.3.x-to-0.4.0/README.md)
- [How to upgrade from 0.4 to 0.5](0.4.x-to-0.5.0/README.md)
- [How to upgrade from 0.5 to 0.6](0.5.x-to-0.6.0/README.md)
- [How to upgrade from 0.6 to 0.7](0.6.x-to-0.7.0/README.md)
- [How to upgrade from 0.7 to 0.8](0.7.x-to-0.8.0/README.md)
- [How to upgrade from 0.8 to 0.9](0.8.x-to-0.9.0/README.md)

## Add a topic for a caller-visible change

Each upgrade has one directory here, named `<current>.x-to-<next>.0`.
`<current>` is the latest published minor release, and `<next>` is the release
that ships the change. A caller-visible change adds a topic file to the
directory of its upgrade and links the file from that directory's `README.md`.
The file name says what the topic covers and has no `unreleased-` prefix.

If the directory for the next release does not exist yet, create it with an
overview in `README.md` and add it to the list above.

[How to add a migration guide](../../CONTRIBUTING.md#how-to-add-a-migration-guide)
