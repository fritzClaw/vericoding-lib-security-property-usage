# katas/

One verified crate per application component: `katas/NNNN-name/`, created with

```sh
tools/vc.py new 0001-some-component
```

See the top-level `README.md` for the pipeline. Don't delete this file while
`katas/` has no crate yet: the workspace member glob `katas/*` needs at least
one match, and Cargo ignores plain files.
