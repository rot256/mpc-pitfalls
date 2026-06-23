# Templates

Use these Markdown templates when adding new entries:

- `BUG_TEMPLATE.md`: for concrete real-world bugs under `content/bugs/`.
- `PITFALL_TEMPLATE.md`: for reusable pitfall patterns under `content/pitfalls/`.

A bug is just an id (its file name) plus its own metadata. The link lives on the
pitfall side: a pitfall lists a bug's id in its `bugs` array (all associated bugs,
which populate the tracker) and in its `display` array (the subset shown inline on
the homepage). A bug's tracker category is inherited from its parent pitfall.
