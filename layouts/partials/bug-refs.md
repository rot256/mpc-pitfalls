{{/*
    Builds a slice of Markdown links for a bug's references.
    Reads source, cve, issue, pr, and commit from the page's frontmatter.

    Usage: {{ $refs := partial "bug-refs.md" . }}
*/}}
{{ $page := . }}
{{ $repo := $page.Params.repository }}
{{ $refs := slice }}

{{ with $page.Params.source }}
    {{ range . }}
        {{ $refs = $refs | append (printf "[%s](%s)" .name .url) }}
    {{ end }}
{{ end }}

{{ with $page.Params.cve }}
    {{ $refs = $refs | append (printf "[%s](%s)" .name .url) }}
{{ end }}

{{ with $page.Params.issue }}
    {{ $issues := . }}
    {{ if not (reflect.IsSlice .) }}{{ $issues = slice . }}{{ end }}
    {{ range $issues }}
        {{ $issue := . }}
        {{ with $repo }}{{ $refs = $refs | append (printf "[Issue #%v](%s/issues/%v)" $issue $repo $issue) }}{{ end }}
    {{ end }}
{{ end }}

{{ with $page.Params.pr }}
    {{ $prs := . }}
    {{ if not (reflect.IsSlice .) }}{{ $prs = slice . }}{{ end }}
    {{ range $prs }}
        {{ $pr := . }}
        {{ with $repo }}{{ $refs = $refs | append (printf "[PR #%v](%s/pull/%v)" $pr $repo $pr) }}{{ end }}
    {{ end }}
{{ end }}

{{ with $page.Params.commit }}
    {{ $commits := . }}
    {{ if not (reflect.IsSlice .) }}{{ $commits = slice . }}{{ end }}
    {{ range $commits }}
        {{ $commit := . }}
        {{ $short := substr $commit 0 7 }}
        {{ with $repo }}{{ $refs = $refs | append (printf "commit [`%s`](%s/commit/%s)" $short $repo $commit) }}{{ end }}
    {{ end }}
{{ end }}

{{ return $refs }}
